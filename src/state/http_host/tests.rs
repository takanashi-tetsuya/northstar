//! The documented public HTTP surface against the routers that compose it.

#[test]
fn openapi_contract_lists_exact_router_methods() {
    use std::collections::BTreeSet;

    let document = include_str!("../../../docs/openapi.yaml");
    assert!(document.starts_with("openapi: 3.1.0\n"));
    assert!(document.contains("\npaths:\n"));
    assert!(document.contains("\ncomponents:\n"));
    assert!(!document.contains('\t'));

    let mut current_path = None;
    let mut documented = BTreeSet::new();
    for line in document.lines() {
        if let Some(path) = line
            .strip_prefix("  ")
            .and_then(|line| line.strip_suffix(':'))
            .filter(|line| line.starts_with('/'))
        {
            current_path = Some(path);
            continue;
        }
        if line == "components:" {
            current_path = None;
            continue;
        }
        let Some(path) = current_path else { continue };
        let method = match line {
            "    get:" => Some("GET"),
            "    post:" => Some("POST"),
            "    put:" => Some("PUT"),
            "    patch:" => Some("PATCH"),
            "    delete:" => Some("DELETE"),
            "    options:" => Some("OPTIONS"),
            _ => None,
        };
        if let Some(method) = method {
            documented.insert(format!("{method} {path}"));
        }
    }

    let router_source = [
        include_str!("../../../crates/edges/northstar-http/src/lib.rs"),
        include_str!("../../../crates/edges/northstar-http/src/route_composition.rs"),
        include_str!("../http_host.rs"),
    ]
    .join("\n");
    let mut router_contract = BTreeSet::new();
    let mut search_from = 0;
    while let Some(relative) = router_source[search_from..].find(".route(") {
        let route_offset = search_from + relative;
        let opening = route_offset + ".route".len();
        let mut depth = 0_u32;
        let mut quoted = false;
        let mut escaped = false;
        let mut closing = None;
        for (offset, character) in router_source[opening..].char_indices() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    quoted = false;
                }
                continue;
            }
            match character {
                '"' => quoted = true,
                '(' => depth = depth.saturating_add(1),
                ')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        closing = Some(opening + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        let closing = closing.expect("balanced route call");
        let call = &router_source[opening + 1..closing];
        let quote = call.find('"').expect("route path opening quote");
        let path_tail = &call[quote + 1..];
        let path_end = path_tail.find('"').expect("route path closing quote");
        let path = &path_tail[..path_end];
        let handler = &path_tail[path_end + 1..];
        for (method, needles) in [
            ("GET", [" get(", ".get("]),
            ("POST", [" post(", ".post("]),
            ("PUT", [" put(", ".put("]),
            ("PATCH", [" patch(", ".patch("]),
            ("DELETE", [" delete(", ".delete("]),
            ("OPTIONS", [" options(", ".options("]),
        ] {
            if needles.iter().any(|needle| handler.contains(needle)) {
                router_contract.insert(format!("{method} {path}"));
            }
        }
        search_from = closing + 1;
    }
    assert!(!router_contract.is_empty(), "router parser found no routes");
    assert_eq!(documented, router_contract);

    for required_contract in [
        "schema: { $ref: \"#/components/schemas/ReportModerationPatch\" }",
        "schema: { $ref: \"#/components/schemas/AppealModerationPatch\" }",
        "additionalProperties: false",
        "name: cursor",
        "OperationTarget:",
    ] {
        assert!(document.contains(required_contract));
    }
    assert!(
        !document.contains("name: offset"),
        "offset pagination must not reappear in the public contract"
    );
}
