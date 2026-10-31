//! Parse and render subscription options and node configuration forms.

use super::*;

pub(super) fn subscription_options(subscription: &PubSubSubscription) -> PubSubSubscriptionOptions {
    PubSubSubscriptionOptions {
        deliver: subscription.deliver,
        digest: subscription.digest,
        digest_frequency: subscription.digest_frequency,
        expire: subscription.expire,
        include_body: subscription.include_body,
        show_values: subscription.show_values.clone(),
        subscription_type: subscription.subscription_type.clone(),
        subscription_depth: subscription.subscription_depth,
    }
}

pub(super) fn parse_subscription_options(
    form: Node<'_, '_>,
    mut options: PubSubSubscriptionOptions,
    node_type: &str,
    supports_include_body: bool,
) -> std::result::Result<PubSubSubscriptionOptions, PubSubReply> {
    if !valid_submit_form_structure(form) || has_duplicate_fields(form) {
        return Err(PubSubReply::Error("bad-request"));
    }
    let fields = data_form_fields(form);
    if first_field(&fields, "FORM_TYPE") != Some(SUBSCRIBE_OPTIONS_FORM) {
        return Err(PubSubReply::Error("bad-request"));
    }
    for field in [
        "FORM_TYPE",
        "pubsub#deliver",
        "pubsub#digest",
        "pubsub#digest_frequency",
        "pubsub#expire",
        "pubsub#include_body",
        "pubsub#subscription_type",
        "pubsub#subscription_depth",
    ] {
        if fields.get(field).is_some_and(|values| values.len() != 1) {
            return Err(invalid_subscription_options());
        }
    }
    for (field, target) in [
        ("pubsub#deliver", &mut options.deliver),
        ("pubsub#digest", &mut options.digest),
        ("pubsub#include_body", &mut options.include_body),
    ] {
        if let Some(value) = first_field(&fields, field) {
            *target = parse_bool(Some(value)).ok_or_else(invalid_subscription_options)?;
        }
    }
    if options.include_body && !supports_include_body {
        return Err(invalid_subscription_options());
    }
    if let Some(value) = first_field(&fields, "pubsub#digest_frequency") {
        options.digest_frequency = value
            .parse::<i32>()
            .ok()
            .filter(|value| (1_000..=86_400_000).contains(value))
            .ok_or_else(invalid_subscription_options)?;
    }
    if let Some(value) = first_field(&fields, "pubsub#expire") {
        options.expire = if value.is_empty() {
            None
        } else if value == "presence" {
            // Presence-scoped leases require full-JID subscription state,
            // which this service intentionally does not advertise.
            return Err(invalid_subscription_options());
        } else {
            let now = chrono::Utc::now();
            let expiry = chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| invalid_subscription_options())?
                .with_timezone(&chrono::Utc);
            if expiry <= now {
                return Err(invalid_subscription_options());
            }
            // XEP-0060 requires a service with a maximum lease term to clamp
            // an overlong request rather than reject it. A finite policy also
            // prevents effectively immortal rows chosen by remote entities.
            Some(expiry.min(now + chrono::Duration::days(MAX_SUBSCRIPTION_LEASE_DAYS)))
        };
    }
    if let Some(values) = fields.get("pubsub#show-values") {
        if values.is_empty()
            || values.len() > 5
            || values
                .iter()
                .any(|value| !matches!(value.as_str(), "away" | "chat" | "dnd" | "online" | "xa"))
        {
            return Err(invalid_subscription_options());
        }
        let mut unique = BTreeSet::new();
        unique.extend(values.iter().cloned());
        options.show_values = unique.into_iter().collect();
    }
    if let Some(value) = first_field(&fields, "pubsub#subscription_type") {
        let valid = if node_type == "collection" {
            matches!(value, "items" | "nodes" | "all")
        } else {
            value == "items"
        };
        if !valid {
            return Err(invalid_subscription_options());
        }
        options.subscription_type = value.to_owned();
    }
    if let Some(value) = first_field(&fields, "pubsub#subscription_depth") {
        if node_type != "collection" {
            return Err(invalid_subscription_options());
        }
        options.subscription_depth = if value == "all" {
            None
        } else {
            Some(
                value
                    .parse::<i32>()
                    .ok()
                    .filter(|value| *value >= 0)
                    .ok_or_else(invalid_subscription_options)?,
            )
        };
    }
    Ok(options)
}

pub(super) fn subscription_options_form(
    options: &PubSubSubscriptionOptions,
    form_type: &str,
    supports_include_body: bool,
    node_type: &str,
) -> String {
    let expiry = options
        .expire
        .map(|value| value.to_rfc3339())
        .unwrap_or_default();
    let depth = options
        .subscription_depth
        .map(|value| value.to_string())
        .unwrap_or_else(|| "all".to_owned());
    let mut form = XmlElement::namespaced("x", NS_DATA)
        .attr("type", form_type)
        .child(data_field_element(
            "FORM_TYPE",
            Some("hidden"),
            [SUBSCRIBE_OPTIONS_FORM],
        ))
        .child(data_field_element(
            "pubsub#deliver",
            Some("boolean"),
            [bool_text(options.deliver)],
        ))
        .child(data_field_element(
            "pubsub#digest",
            Some("boolean"),
            [bool_text(options.digest)],
        ))
        .child(data_field_element(
            "pubsub#digest_frequency",
            Some("text-single"),
            [options.digest_frequency.to_string()],
        ))
        .child(data_field_element(
            "pubsub#expire",
            Some("text-single"),
            [expiry],
        ));
    if supports_include_body {
        form.push_child(data_field_element(
            "pubsub#include_body",
            Some("boolean"),
            [bool_text(options.include_body)],
        ));
    }
    form.push_child(data_field_element(
        "pubsub#show-values",
        Some("list-multi"),
        options.show_values.iter(),
    ));
    if node_type == "collection" {
        form.push_child(data_field_element(
            "pubsub#subscription_type",
            Some("list-single"),
            [&options.subscription_type],
        ));
        form.push_child(data_field_element(
            "pubsub#subscription_depth",
            Some("text-single"),
            [depth],
        ));
    }
    form.finish()
}

pub(super) fn supports_include_body(node: &PubSubNode) -> bool {
    node.payload_type.as_deref() == Some("http://www.w3.org/2005/Atom")
}

pub(super) fn parse_node_config(
    container: Node<'_, '_>,
    config: PubSubNodeConfig,
) -> std::result::Result<PubSubNodeConfig, &'static str> {
    parse_node_config_form(container, config, NODE_CONFIG_FORM, false)
}

pub(super) fn parse_publish_options(
    container: Node<'_, '_>,
    config: PubSubNodeConfig,
) -> std::result::Result<PubSubNodeConfig, &'static str> {
    parse_node_config_form(container, config, PUBLISH_OPTIONS_FORM, true)
}

pub(super) fn parse_node_config_form(
    container: Node<'_, '_>,
    mut config: PubSubNodeConfig,
    expected_form_type: &str,
    reject_unknown_fields: bool,
) -> std::result::Result<PubSubNodeConfig, &'static str> {
    if !has_only_whitespace_text(container) {
        return Err("bad-request");
    }
    let mut children = container.children().filter(|node| node.is_element());
    let Some(form) = children.next() else {
        return Ok(config);
    };
    if children.next().is_some()
        || !valid_submit_form_structure(form)
        || form.tag_name().namespace() != Some(NS_DATA)
    {
        return Err("bad-request");
    }
    if has_duplicate_fields(form) {
        return Err("bad-request");
    }
    let fields = data_form_fields(form);
    for name in [
        "FORM_TYPE",
        "pubsub#access_model",
        "pubsub#publish_model",
        "pubsub#max_items",
        "pubsub#title",
        "pubsub#description",
        "pubsub#deliver_payloads",
        "pubsub#notify_delete",
        "pubsub#notify_retract",
        "pubsub#persist_items",
        "pubsub#send_last_published_item",
        "pubsub#node_type",
        "pubsub#deliver_notifications",
        "pubsub#notify_config",
        "pubsub#notify_sub",
        "pubsub#language",
        "pubsub#type",
        "pubsub#max_payload_size",
        "pubsub#children_max",
        "pubsub#children_association_policy",
    ] {
        if fields.get(name).is_some_and(|values| values.len() != 1) {
            return Err("bad-request");
        }
    }
    if first_field(&fields, "FORM_TYPE") != Some(expected_form_type) {
        return Err("bad-request");
    }
    if reject_unknown_fields {
        const KNOWN: &[&str] = &[
            "FORM_TYPE",
            "pubsub#access_model",
            "pubsub#publish_model",
            "pubsub#max_items",
            "pubsub#title",
            "pubsub#description",
            "pubsub#deliver_payloads",
            "pubsub#notify_delete",
            "pubsub#notify_retract",
            "pubsub#persist_items",
            "pubsub#send_last_published_item",
            "pubsub#node_type",
            "pubsub#deliver_notifications",
            "pubsub#notify_config",
            "pubsub#notify_sub",
            "pubsub#language",
            "pubsub#type",
            "pubsub#max_payload_size",
            "pubsub#children_max",
            "pubsub#children_association_policy",
            "pubsub#children_association_whitelist",
            "pubsub#collection",
            "pubsub#children",
        ];
        if fields.keys().any(|name| !KNOWN.contains(&name.as_str())) {
            return Err("bad-request");
        }
    }
    if let Some(value) = first_field(&fields, "pubsub#access_model") {
        if !matches!(value, "open" | "authorize" | "whitelist") {
            return Err("unsupported-access-model");
        }
        config.access_model = value.to_owned();
    }
    if let Some(value) = first_field(&fields, "pubsub#publish_model") {
        if !matches!(value, "open" | "publishers" | "subscribers") {
            return Err("not-acceptable");
        }
        config.publish_model = value.to_owned();
    }
    if let Some(value) = first_field(&fields, "pubsub#max_items") {
        config.max_items = if value == "max" {
            1_000
        } else {
            value
                .parse::<i32>()
                .ok()
                .filter(|value| (1..=1_000).contains(value))
                .ok_or("not-acceptable")?
        };
    }
    if let Some(value) = first_field(&fields, "pubsub#title") {
        if value.len() > MAX_TITLE_BYTES || value.chars().any(char::is_control) {
            return Err("not-acceptable");
        }
        config.title = (!value.is_empty()).then(|| value.to_owned());
    }
    if let Some(value) = first_field(&fields, "pubsub#description") {
        if value.len() > MAX_DESCRIPTION_BYTES || value.chars().any(char::is_control) {
            return Err("not-acceptable");
        }
        config.description = (!value.is_empty()).then(|| value.to_owned());
    }
    for (field, target) in [
        ("pubsub#deliver_payloads", &mut config.deliver_payloads),
        ("pubsub#notify_delete", &mut config.notify_delete),
        ("pubsub#notify_retract", &mut config.notify_retract),
        ("pubsub#persist_items", &mut config.persist_items),
    ] {
        if let Some(value) = first_field(&fields, field) {
            *target = parse_bool(Some(value)).ok_or("not-acceptable")?;
        }
    }
    if let Some(value) = first_field(&fields, "pubsub#send_last_published_item") {
        if !matches!(value, "never" | "on_sub" | "on_sub_and_presence") {
            return Err("not-acceptable");
        }
        config.send_last_published_item = value.to_owned();
    }
    if let Some(value) = first_field(&fields, "pubsub#node_type") {
        if !matches!(value, "leaf" | "collection") {
            return Err("not-acceptable");
        }
        config.node_type = value.to_owned();
    }
    for (field, target) in [
        (
            "pubsub#deliver_notifications",
            &mut config.deliver_notifications,
        ),
        ("pubsub#notify_config", &mut config.notify_config),
        ("pubsub#notify_sub", &mut config.notify_sub),
    ] {
        if let Some(value) = first_field(&fields, field) {
            *target = parse_bool(Some(value)).ok_or("not-acceptable")?;
        }
    }
    if let Some(value) = first_field(&fields, "pubsub#language") {
        if !value.is_empty() && !northstar_xmpp_types::text::valid_language_tag(value) {
            return Err("not-acceptable");
        }
        config.language = (!value.is_empty()).then(|| value.to_owned());
    }
    if let Some(value) = first_field(&fields, "pubsub#type") {
        if value.len() > 512 || value.chars().any(char::is_control) {
            return Err("not-acceptable");
        }
        config.payload_type = (!value.is_empty()).then(|| value.to_owned());
    }
    if let Some(value) = first_field(&fields, "pubsub#max_payload_size") {
        config.max_payload_size = value
            .parse::<i32>()
            .ok()
            .filter(|value| (0..=MAX_ITEM_XML_BYTES as i32).contains(value))
            .ok_or("not-acceptable")?;
    }
    if let Some(value) = first_field(&fields, "pubsub#children_max") {
        config.children_max = if value == "max" {
            1_000
        } else {
            value
                .parse::<i32>()
                .ok()
                .filter(|value| (0..=1_000).contains(value))
                .ok_or("not-acceptable")?
        };
    }
    if let Some(value) = first_field(&fields, "pubsub#children_association_policy") {
        config.children_association_policy = match value {
            // XEP-0248 registers the wire value as `owners`. PostgreSQL keeps
            // the older compact internal enum `owner`; normalize only at the
            // protocol boundary so existing durable rows need no migration.
            "owners" => "owner".to_owned(),
            "whitelist" | "all" => value.to_owned(),
            _ => return Err("not-acceptable"),
        };
    }
    if let Some(values) = fields.get("pubsub#children_association_whitelist") {
        if values.len() > 100
            || values
                .iter()
                .any(|jid| !valid_bare_jid(jid) || jid.len() > 3071)
        {
            return Err("not-acceptable");
        }
        config.children_association_whitelist = values
            .iter()
            .map(|jid| normalized_bare(jid).map_err(|_| "not-acceptable"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
    }
    for (field, target) in [
        ("pubsub#collection", &mut config.collections),
        ("pubsub#children", &mut config.children),
    ] {
        if let Some(values) = fields.get(field) {
            if values.len() > 1_000
                || values
                    .iter()
                    .any(|node| !node.is_empty() && valid_node_id(Some(node)).is_none())
            {
                return Err("not-acceptable");
            }
            *target = values
                .iter()
                .filter(|node| !node.is_empty())
                .cloned()
                .collect();
        }
    }
    if config.node_type == "collection" {
        config.persist_items = false;
        config.deliver_payloads = false;
    } else if !config.children.is_empty() {
        return Err("not-allowed");
    }
    if !config.persist_items {
        config.send_last_published_item = "never".to_owned();
    }
    Ok(config)
}

pub(super) fn data_form_fields(form: Node<'_, '_>) -> HashMap<String, Vec<String>> {
    let mut fields = HashMap::new();
    for field in form.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "field"
            && node.tag_name().namespace() == Some(NS_DATA)
    }) {
        let Some(var) = field.attribute("var") else {
            continue;
        };
        let values = field
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "value"
                    && node.tag_name().namespace() == Some(NS_DATA)
            })
            .map(|node| node.text().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        fields.insert(var.to_owned(), values);
    }
    fields
}

pub(super) fn has_duplicate_fields(form: Node<'_, '_>) -> bool {
    let mut names = BTreeSet::new();
    form.children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "field"
                && node.tag_name().namespace() == Some(NS_DATA)
        })
        .filter_map(|field| field.attribute("var"))
        .any(|name| !names.insert(name))
}

pub(super) fn first_field<'a>(
    fields: &'a HashMap<String, Vec<String>>,
    name: &str,
) -> Option<&'a str> {
    fields.get(name)?.first().map(String::as_str)
}

pub(super) fn node_config_form(config: &PubSubNodeConfig, form_type: &str) -> String {
    northstar_pubsub_application::service::pubsub_node_config_form(config, form_type)
}
