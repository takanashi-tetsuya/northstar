//! Coordinate imports, prepare credentials, and securely load bounded PIE documents and includes.

use super::*;

pub(super) async fn import(
    pool: &PgPool,
    runtime: &ImportRuntime<'_>,
    options: &ImportOptions,
) -> Result<()> {
    let domain = jid::prepare_domainpart(runtime.domain)?;
    let root = secure_root(&options.input, options.root.as_deref())?;
    let input = secure_existing_path(&root, &options.input)?;
    let mut budget = LoadBudget::default();
    let mut document = ImportDocument::default();
    load_server_document(&root, &input, 0, &domain, &mut budget, &mut document)?;
    if document.users.is_empty() {
        bail!("PIE import contains no users for {domain}");
    }
    document
        .users
        .sort_by(|left, right| left.username.cmp(&right.username));
    for window in document.users.windows(2) {
        if window[0].username == window[1].username {
            bail!("PIE contains duplicate user {:?}", window[0].username);
        }
    }
    if options.unknown == UnknownPolicy::Fail && !document.warnings.is_empty() {
        bail!(
            "PIE contains unsupported data:\n{}",
            document.warnings.join("\n")
        );
    }
    for warning in &document.warnings {
        eprintln!("warning: {warning}");
    }
    let mut prepared = Vec::with_capacity(document.users.len());
    for user in document.users {
        prepared.push(prepare_user(
            user,
            runtime.scram_iterations,
            options.allow_plaintext_passwords,
        )?);
    }
    let source = input
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("[non-utf8]");
    let (imported, skipped) = db::pie::persist_import(
        pool,
        &domain,
        source,
        prepared,
        options.conflict,
        options.dry_run,
        document.warnings.len(),
    )
    .await?;
    if options.dry_run {
        eprintln!(
            "PIE dry-run validated {imported} user(s), skipped {skipped}, and rolled back every database change"
        );
    } else {
        eprintln!("PIE import committed {imported} user(s); skipped {skipped}");
    }
    Ok(())
}

pub(super) fn prepare_user(
    user: PieUser,
    iterations: u32,
    allow_plaintext: bool,
) -> Result<PreparedUser> {
    if let Some(password) = user.plaintext_password.as_deref() {
        if !allow_plaintext {
            bail!(
                "PIE user {:?} contains a plaintext password; explicit --allow-plaintext-passwords is required",
                user.username
            );
        }
        let credentials =
            auth::hash_password(password, true, iterations, false).with_context(|| {
                format!(
                    "invalid plaintext password for PIE user {:?}",
                    user.username
                )
            })?;
        let (password_hash, iterations, salt, stored_key, server_key) =
            credentials.into_sha256_parts();
        return Ok(PreparedUser {
            data: user,
            password_hash,
            scram: ScramCredential {
                iterations,
                salt,
                stored_key,
                server_key,
            },
        });
    }
    let scram = user.scram.as_ref().context(format!(
        "PIE user {:?} has neither an allowed plaintext password nor SCRAM-SHA-256 credentials",
        user.username
    ))?;
    Ok(PreparedUser {
        password_hash: SCRAM_ONLY_PASSWORD_HASH.to_owned(),
        scram: ScramCredential {
            iterations: scram.iterations,
            salt: scram.salt.clone(),
            stored_key: scram.stored_key.clone(),
            server_key: scram.server_key.clone(),
        },
        data: user,
    })
}

pub(super) fn secure_root(input: &Path, root: Option<&Path>) -> Result<PathBuf> {
    let requested = root.map(Path::to_path_buf).unwrap_or_else(|| {
        input
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });
    if fs::symlink_metadata(&requested)?.file_type().is_symlink() {
        bail!("PIE security root must not be a symlink");
    }
    requested
        .canonicalize()
        .context("could not resolve PIE security root")
}

pub(super) fn secure_existing_path(root: &Path, requested: &Path) -> Result<PathBuf> {
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()?.join(requested)
    };
    if !candidate.starts_with(root) {
        bail!("PIE input path must be lexically below the configured security root");
    }
    // Inspect the path exactly as supplied before canonicalization. Once a
    // symlink has been canonicalized its identity is lost, so checking only
    // the resolved path would silently accept a link whose target remains
    // inside the security root.
    reject_symlink_components(root, &candidate)?;
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("could not resolve {}", candidate.display()))?;
    if !canonical.starts_with(root) {
        bail!("PIE input escapes the configured security root");
    }
    if !canonical.is_file() {
        bail!("PIE input is not a regular file");
    }
    Ok(canonical)
}

pub(super) fn reject_symlink_components(root: &Path, path: &Path) -> Result<()> {
    let relative = path
        .strip_prefix(root)
        .context("path escaped security root")?;
    if relative.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        bail!("PIE path contains a non-local path component");
    }
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            bail!("PIE refuses symlink path component {}", current.display());
        }
    }
    Ok(())
}

pub(super) fn resolve_include(root: &Path, parent: &Path, href: &str) -> Result<PathBuf> {
    if href.is_empty() || href.contains(['?', '#', '\\']) || href.contains("://") {
        bail!("unsafe XInclude href {href:?}");
    }
    let decoded = percent_decode(href)?;
    let relative = Path::new(&decoded);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("XInclude href must be a relative URI below the security root");
    }
    let candidate = parent
        .parent()
        .context("XInclude parent has no directory")?
        .join(relative);
    if !candidate.starts_with(root) {
        bail!("XInclude {href:?} escapes the security root");
    }
    // Check the unresolved candidate. Canonicalization follows symlinks and
    // therefore cannot be used to prove that the original include path was
    // link-free.
    reject_symlink_components(root, &candidate)?;
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("could not resolve XInclude {href:?}"))?;
    if !canonical.starts_with(root) {
        bail!("XInclude {href:?} escapes the security root");
    }
    if !canonical.is_file() {
        bail!("XInclude {href:?} is not a regular file");
    }
    Ok(canonical)
}

pub(super) fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = *bytes.get(index + 1).context("truncated percent escape")?;
            let lo = *bytes.get(index + 2).context("truncated percent escape")?;
            decoded.push((hex(hi)? << 4) | hex(lo)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let value = String::from_utf8(decoded).context("XInclude href is not UTF-8")?;
    if value.contains('\0') {
        bail!("XInclude href contains NUL");
    }
    Ok(value)
}

pub(super) fn hex(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => bail!("invalid percent escape"),
    }
}

pub(super) fn read_xml(path: &Path, budget: &mut LoadBudget) -> Result<String> {
    if budget.files >= MAX_FILES {
        bail!("PIE exceeds the {MAX_FILES} file limit");
    }
    if !budget.seen.insert(path.to_path_buf()) {
        bail!(
            "PIE contains an XInclude cycle or duplicate include: {}",
            path.display()
        );
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_FILE_BYTES {
        bail!(
            "PIE file {} exceeds {} MiB",
            path.display(),
            MAX_FILE_BYTES / 1024 / 1024
        );
    }
    budget.total_bytes = budget
        .total_bytes
        .checked_add(metadata.len())
        .context("PIE byte counter overflow")?;
    if budget.total_bytes > MAX_TOTAL_BYTES {
        bail!(
            "PIE input exceeds {} MiB total",
            MAX_TOTAL_BYTES / 1024 / 1024
        );
    }
    budget.files += 1;
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        bail!("PIE file grew beyond its size limit while reading");
    }
    let xml = String::from_utf8(bytes).context("PIE XML is not UTF-8")?;
    reject_dtd(&xml)?;
    Ok(xml)
}

pub(super) fn load_server_document(
    root: &Path,
    path: &Path,
    depth: usize,
    domain: &str,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    include_depth(depth)?;
    let xml = read_xml(path, budget)?;
    let document = parse_bounded(&xml, path, budget)?;
    let root_node = document.root_element();
    if root_node.tag_name().name() != "server-data"
        || root_node.tag_name().namespace() != Some(PIE_NS)
    {
        bail!("PIE root must be server-data in {PIE_NS}");
    }
    for child in element_children(root_node)? {
        if is_include(child) {
            let include = parse_include(root, path, child)?;
            load_host_document(root, &include, depth + 1, domain, budget, output)?;
        } else if child.tag_name().name() == "host" && child.tag_name().namespace() == Some(PIE_NS)
        {
            parse_host(root, path, child, depth, domain, budget, output)?;
        } else {
            unsupported(
                output,
                format!(
                    "unsupported server-data child {{{}}}{}",
                    child.tag_name().namespace().unwrap_or(""),
                    child.tag_name().name()
                ),
            );
        }
    }
    Ok(())
}

pub(super) fn load_host_document(
    root: &Path,
    path: &Path,
    depth: usize,
    domain: &str,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    include_depth(depth)?;
    let xml = read_xml(path, budget)?;
    let document = parse_bounded(&xml, path, budget)?;
    let node = document.root_element();
    if node.tag_name().name() != "host" || node.tag_name().namespace() != Some(PIE_NS) {
        bail!("server-data XInclude must resolve to one PIE host element");
    }
    parse_host(root, path, node, depth, domain, budget, output)
}

pub(super) fn parse_host(
    root: &Path,
    path: &Path,
    node: Node<'_, '_>,
    depth: usize,
    domain: &str,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    only_attributes(node, &["jid"])?;
    let host = node.attribute("jid").context("PIE host is missing jid")?;
    let parsed = jid::CanonicalJid::parse_bare(host)?;
    if parsed.localpart().is_some() || parsed.domainpart() != domain {
        bail!("PIE host {host:?} does not exactly match configured domain {domain:?}");
    }
    for child in element_children(node)? {
        if is_include(child) {
            let include = parse_include(root, path, child)?;
            load_user_document(root, &include, depth + 1, domain, budget, output)?;
        } else if child.tag_name().name() == "user" && child.tag_name().namespace() == Some(PIE_NS)
        {
            push_user(child, domain, budget, output)?;
        } else {
            unsupported(
                output,
                format!(
                    "unsupported host child {{{}}}{}",
                    child.tag_name().namespace().unwrap_or(""),
                    child.tag_name().name()
                ),
            );
        }
    }
    Ok(())
}

pub(super) fn load_user_document(
    _root: &Path,
    path: &Path,
    depth: usize,
    domain: &str,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    include_depth(depth)?;
    let xml = read_xml(path, budget)?;
    let document = parse_bounded(&xml, path, budget)?;
    let node = document.root_element();
    if node.tag_name().name() != "user" || node.tag_name().namespace() != Some(PIE_NS) {
        bail!("host XInclude must resolve to one PIE user element");
    }
    push_user(node, domain, budget, output)
}

pub(super) fn push_user(
    node: Node<'_, '_>,
    domain: &str,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    budget.users += 1;
    if budget.users > MAX_USERS {
        bail!("PIE exceeds the {MAX_USERS} user limit");
    }
    only_attributes(node, &["name", "password"])?;
    let raw_name = node.attribute("name").context("PIE user is missing name")?;
    let username = auth::normalize_username(raw_name)?;
    if username != raw_name {
        bail!("PIE user name {raw_name:?} is not canonical");
    }
    let mut user = PieUser {
        username,
        plaintext_password: node.attribute("password").map(ToOwned::to_owned),
        ..Default::default()
    };
    let account_username = user.username.clone();
    for child in element_children(node)? {
        match (
            child.tag_name().namespace().unwrap_or(""),
            child.tag_name().name(),
        ) {
            (SCRAM_NS, "scram-credentials") => parse_scram(child, &mut user, output)?,
            (ROSTER_NS, "query") => parse_roster(child, &mut user, budget)?,
            (PIE_NS, "offline-messages") => parse_offline(
                child,
                &format!("{account_username}@{domain}"),
                &mut user,
                budget,
            )?,
            (PRIVATE_NS, "query") => parse_private(child, &mut user, budget)?,
            ("vcard-temp", "vCard") => {
                item(budget)?;
                if user.vcard.replace(node_to_xml(child)).is_some() {
                    bail!("duplicate vCard for PIE user");
                }
            }
            (PRIVACY_NS, "query") => parse_privacy(child, &mut user, budget, output)?,
            (CLIENT_NS, "presence") => parse_pending(child, domain, &mut user, budget)?,
            (PUBSUB_OWNER_NS, "pubsub") => parse_pep_owner(child, &mut user, budget, output)?,
            (PUBSUB_NS, "pubsub") => parse_pep_items(child, &mut user, budget)?,
            (MAM_PIE_NS, "archive") => {
                parse_archive(child, &account_username, domain, &mut user, budget)?
            }
            (XINCLUDE_NS, "include") => unsupported(
                output,
                "XInclude below a user is opaque user data and was not processed".to_owned(),
            ),
            (namespace, name) => unsupported(
                output,
                format!("unsupported user child {{{namespace}}}{name}"),
            ),
        }
    }
    output.users.push(user);
    Ok(())
}

pub(super) fn parse_include(root: &Path, parent: &Path, node: Node<'_, '_>) -> Result<PathBuf> {
    only_attributes(node, &["href"])?;
    if node.attribute("parse").is_some() || node.attribute("xpointer").is_some() {
        bail!("PIE only supports XInclude without parse or xpointer");
    }
    if node
        .children()
        .any(|child| child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        bail!("XInclude fallback/content is not supported");
    }
    resolve_include(
        root,
        parent,
        node.attribute("href").context("XInclude missing href")?,
    )
}

pub(super) fn parse_bounded<'a>(
    xml: &'a str,
    path: &Path,
    budget: &mut LoadBudget,
) -> Result<Document<'a>> {
    let document =
        Document::parse(xml).with_context(|| format!("malformed XML in {}", path.display()))?;
    let mut local_nodes = 0_usize;
    let mut max_depth = 0_usize;
    for node in document.descendants() {
        local_nodes += 1;
        let depth = node.ancestors().count();
        max_depth = max_depth.max(depth);
    }
    if max_depth > MAX_XML_DEPTH {
        bail!("PIE XML nesting exceeds {MAX_XML_DEPTH}");
    }
    budget.nodes = budget
        .nodes
        .checked_add(local_nodes)
        .context("PIE node counter overflow")?;
    if budget.nodes > MAX_XML_NODES {
        bail!("PIE exceeds the {MAX_XML_NODES} XML-node limit");
    }
    Ok(document)
}
