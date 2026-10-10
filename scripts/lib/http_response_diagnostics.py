"""Conservative, bounded HTTP/1 summaries of bytes received before recv fails.

This is an observer, not a protocol parser or a success criterion. It never
reads a stream, changes a deadline, or substitutes HTTP completion for recv
EOF. Only an unambiguous Content-Length response is classified as complete;
unsupported framing stays unknown. No response values or body bytes are logged.
"""

import re


MAX_HEADER_BYTES = 65536
_STATUS = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [\t\x20-\x7e\x80-\xff]*")
_FIELD_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def summarize_http_response(chunks):
    """Summarize already-received byte chunks; recv EOF has not been observed.

    At most MAX_HEADER_BYTES are copied. All chunk lengths are counted without
    copying their bodies. Lengths above 20 decimal digits remain unclassified,
    bounding integer conversion independently of the interpreter's settings.
    Duplicate Content-Length, Transfer-Encoding, malformed headers, and
    response kinds needing request context deliberately stay unclassified.
    """
    prefix = bytearray()
    received = 0
    for chunk in chunks:
        received += len(chunk)
        remaining = MAX_HEADER_BYTES - len(prefix)
        if remaining:
            prefix.extend(chunk[:remaining])

    result = {
        "received_bytes": received,
        "header_bytes": None,
        "status": None,
        "framing": "unknown",
        "declared_body_bytes": None,
        "received_body_bytes": None,
        "connection_close": None,
        "http_response_complete": None,
        "receive_phase": "unclassified",
        "recv_eof_observed": False,
        "parse_note": None,
    }
    separator = prefix.find(b"\r\n\r\n")
    if separator < 0:
        if received >= MAX_HEADER_BYTES:
            result["parse_note"] = "header_capture_limit"
        else:
            result["http_response_complete"] = False
            result["receive_phase"] = "awaiting_response_headers"
        return result

    result["header_bytes"] = separator + 4
    result["received_body_bytes"] = received - result["header_bytes"]
    lines = bytes(prefix[:separator]).split(b"\r\n")
    status = _STATUS.fullmatch(lines[0])
    if status is None:
        result["parse_note"] = "invalid_status_line"
        return result
    result["status"] = int(status[1])
    fields = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not _FIELD_NAME.fullmatch(name) or any(
            byte < 32 and byte != 9 or byte == 127 for byte in value
        ):
            result["parse_note"] = "invalid_header_field"
            return result
        name = name.lower()
        if name in (b"content-length", b"transfer-encoding", b"connection"):
            fields.setdefault(name, []).append(value.strip(b" \t"))
    result["connection_close"] = any(
        token.strip().lower() == b"close"
        for value in fields.get(b"connection", [])
        for token in value.split(b",")
    )

    lengths = fields.get(b"content-length", [])
    if len(lengths) == 1 and re.fullmatch(rb"[0-9]{1,20}", lengths[0]):
        result["declared_body_bytes"] = int(lengths[0])
    # TE always prevents a Content-Length-based completion claim, including an
    # empty, malformed, or unsupported TE value. Do not guess decoded lengths.
    if b"transfer-encoding" in fields:
        result["framing"] = "transfer_encoding_unclassified"
        result["parse_note"] = "transfer_encoding_with_content_length" if lengths else "transfer_encoding"
        return result
    if len(lengths) > 1:
        result["parse_note"] = "duplicate_content_length"
        return result
    if lengths and result["declared_body_bytes"] is None:
        result["parse_note"] = "invalid_or_unsupported_content_length"
        return result
    if result["status"] < 200 or result["status"] in (204, 304):
        result["parse_note"] = "response_kind_unclassified"
        return result
    if not lengths:
        result["framing"] = "close_delimited_unclassified"
        return result

    result["framing"] = "content_length"
    declared = result["declared_body_bytes"]
    body = result["received_body_bytes"]
    if body < declared:
        result["http_response_complete"] = False
        result["receive_phase"] = "awaiting_response_body"
    elif body == declared:
        result["http_response_complete"] = True
        result["receive_phase"] = "awaiting_recv_eof"
    else:
        # Extra bytes could belong to another response or indicate bad framing.
        # They are not evidence that this single-response exchange is complete.
        result["parse_note"] = "bytes_after_declared_body"
    return result
