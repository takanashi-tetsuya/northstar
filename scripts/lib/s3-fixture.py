#!/usr/bin/env python3
"""Small SigV4 client for the isolated, versioned MinIO integration fixture.

No cloud SDK, shell credentials or external endpoint defaults are involved.
The endpoint and credential files must be supplied explicitly by the caller.
"""

import argparse
import datetime
import hashlib
import hmac
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


def signing_key(secret: bytes, day: str) -> bytes:
    key = hmac.new(b"AWS4" + secret, day.encode(), hashlib.sha256).digest()
    for label in (b"us-east-1", b"s3", b"aws4_request"):
        key = hmac.new(key, label, hashlib.sha256).digest()
    return key


def request(args, method: str, key: str = "", query=(), body: bytes = b""):
    parsed = urllib.parse.urlsplit(args.endpoint)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("S3 fixture requires an explicit loopback HTTP endpoint")
    if parsed.path or parsed.query or parsed.fragment or parsed.username:
        raise ValueError("S3 fixture endpoint must contain only scheme and authority")
    uri = "/" + urllib.parse.quote(args.bucket, safe="")
    if key:
        uri += "/" + urllib.parse.quote(key, safe="/-_.~")
    canonical_query = urllib.parse.urlencode(sorted(query), quote_via=urllib.parse.quote)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    day = timestamp[:8]
    digest = hashlib.sha256(body).hexdigest()
    headers = {
        "host": parsed.netloc,
        "x-amz-content-sha256": digest,
        "x-amz-date": timestamp,
    }
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted(headers.items()))
    signed_headers = ";".join(sorted(headers))
    canonical = "\n".join(
        (method, uri, canonical_query, canonical_headers, signed_headers, digest)
    )
    scope = f"{day}/us-east-1/s3/aws4_request"
    to_sign = "\n".join(
        ("AWS4-HMAC-SHA256", timestamp, scope, hashlib.sha256(canonical.encode()).hexdigest())
    )
    secret = Path(args.secret_key_file).read_text().strip().encode()
    access = Path(args.access_key_file).read_text().strip()
    signature = hmac.new(signing_key(secret, day), to_sign.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access}/{scope},"
        f"SignedHeaders={signed_headers},Signature={signature}"
    )
    url = args.endpoint + uri + ("?" + canonical_query if canonical_query else "")
    req = urllib.request.Request(url, data=body if method == "PUT" else None,
                                 headers=headers, method=method)
    try:
        # The test endpoint is loopback; inherited CI proxy settings must not
        # route fixture bytes or authentication headers outside the runner.
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            req, timeout=30
        ) as response:
            return response.read(), response.headers
    except urllib.error.HTTPError as error:
        detail = error.read(1024).decode("utf-8", "replace")
        raise RuntimeError(f"isolated S3 fixture {method} {uri} failed: HTTP {error.code}: {detail}") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--access-key-file", required=True)
    parser.add_argument("--secret-key-file", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("create-versioned-bucket")
    put = sub.add_parser("put")
    put.add_argument("key")
    put.add_argument("file", type=Path)
    get = sub.add_parser("get")
    get.add_argument("key")
    get.add_argument("version")
    get.add_argument("file", type=Path)
    head = sub.add_parser("head")
    head.add_argument("key")
    head.add_argument("version")
    delete = sub.add_parser("delete-version")
    delete.add_argument("key")
    delete.add_argument("version")
    args = parser.parse_args()
    if not args.bucket.isascii() or not args.bucket.replace("-", "").isalnum():
        parser.error("bucket must be a simple fixture-owned DNS label")
    if args.command == "create-versioned-bucket":
        request(args, "PUT")
        body = (b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                b"<Status>Enabled</Status></VersioningConfiguration>")
        request(args, "PUT", query=[("versioning", "")], body=body)
        response, _ = request(args, "GET", query=[("versioning", "")])
        root = ET.fromstring(response)
        status = root.find("{http://s3.amazonaws.com/doc/2006-03-01/}Status")
        if status is None or status.text != "Enabled":
            raise RuntimeError("fixture bucket versioning was not enabled")
    elif args.command == "put":
        _, headers = request(args, "PUT", key=args.key, body=args.file.read_bytes())
        version = headers.get("x-amz-version-id")
        if not version or version == "null":
            raise RuntimeError("MinIO did not return a non-null object version")
        print(version)
    elif args.command in {"get", "head"}:
        query = [] if args.version == "latest" else [("versionId", args.version)]
        body, headers = request(args, "GET" if args.command == "get" else "HEAD",
                                key=args.key, query=query)
        version = headers.get("x-amz-version-id")
        if version != args.version and args.version != "latest":
            raise RuntimeError("MinIO returned an unexpected object version")
        if args.command == "get":
            args.file.write_bytes(body)
        print(version)
    elif args.command == "delete-version":
        if not args.version or args.version == "latest":
            parser.error("delete-version requires an exact version ID")
        _, headers = request(args, "DELETE", key=args.key,
                             query=[("versionId", args.version)])
        if headers.get("x-amz-version-id") != args.version:
            raise RuntimeError("MinIO deleted an unexpected object version")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, ET.ParseError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
