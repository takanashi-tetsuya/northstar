import re
import os

with open('src/xmpp/protocol.rs', 'r', encoding='utf-8') as f:
    code = f.read()

def find_end_brace(text, start_idx):
    brace_count = 0
    in_str = False
    in_char = False
    escape = False
    for i in range(start_idx, len(text)):
        c = text[i]
        if escape:
            escape = False
            continue
        if c == '\\':
            escape = True
            continue
            
        if not in_str and not in_char:
            if c == '"':
                in_str = True
            elif c == "'":
                in_char = True
            elif c == '{':
                brace_count += 1
            elif c == '}':
                brace_count -= 1
                if brace_count == 0:
                    return i
        else:
            if in_str and c == '"':
                in_str = False
            elif in_char and c == "'":
                in_char = False
    return -1

def extract_funcs(text):
    funcs = {}
    idx = 0
    while True:
        match = re.search(r'^\s*(pub(?:\s*\([^)]+\))?\s+)?(?:async\s+)?fn\s+([a-zA-Z0-9_]+)\s*<?[^({]*\(', text[idx:], re.MULTILINE)
        if not match:
            break
        
        start_sig = idx + match.start()
        func_name = match.group(2)
        
        brace_start = text.find('{', start_sig)
        if brace_start == -1:
            break
            
        end_brace = find_end_brace(text, brace_start)
        if end_brace == -1:
            break
            
        funcs[func_name] = text[start_sig:end_brace+1].strip()
        idx = end_brace + 1
    return funcs

impl_start = code.find('impl ProtocolSession {')
if impl_start == -1:
    print('Could not find impl ProtocolSession')
    exit(1)

brace_start = code.find('{', impl_start)
impl_end = find_end_brace(code, brace_start)

before_impl = code[:impl_start]
impl_body = code[brace_start+1:impl_end]
after_impl = code[impl_end+1:]

impl_funcs = extract_funcs(impl_body)
util_funcs = extract_funcs(after_impl)

# Map functions to files based on the plan
modules = {
    'dispatch': ['handle', 'iq'],
    'roster': ['roster_get', 'roster_set', 'push_roster_item', 'push_roster_removal', 'push_roster'],
    'discovery': ['disco_info', 'disco_items'],
    'vcard': ['vcard_get', 'vcard_set'],
    'pep': ['pep_publish', 'pep_get'],
    'blocking': ['blocklist', 'block', 'unblock', 'push_blocking_change', 'notify_blocking_presence'],
    'mam': ['mam'],
    'messaging': ['message', 'send_sent_carbons', 'send_received_carbons'],
    'presence': ['presence', 'update_remote_presence_subscription', 'update_presence_subscription', 'send_current_availability'],
    'muc': ['muc_message', 'muc_owner_get', 'muc_owner_set', 'muc_domain', 'muc_presence', 'muc_occupant_key', 'muc_presence_stanza', 'muc_destroy_presence'],
    'sm': ['stream_management', 'resume', 'acknowledge'],
    'upload': ['upload_domain', 'http_upload_slot'],
    'misc': ['register', 'change_password', 'bind', 'set_carbons', 'enable_push', 'disable_push', 'notify_push']
}

unmapped_impl = []
for name in impl_funcs:
    found = False
    for mod_funcs in modules.values():
        if name in mod_funcs:
            found = True
            break
    if not found:
        unmapped_impl.append(name)

xml_util_funcs = []
for name in util_funcs:
    if name not in ['sender_is_injected_into_self_closing_presence', 'encrypted_archive_removes_plaintext_children', 'no_store_hints_disable_persistence', 'subscription_directions_combine_and_split', 'stream_management_counts_only_stanzas', 'private_messages_do_not_generate_carbons', 'rsm_empty_before_requests_latest_page']:
        xml_util_funcs.append(name)

os.makedirs('src/xmpp/split_output', exist_ok=True)

with open('src/xmpp/split_output/xml_util.rs', 'w', encoding='utf-8') as f:
    f.write("use roxmltree::Node;\nuse std::time::Instant;\n\n")
    for name in xml_util_funcs:
        f.write(util_funcs[name] + "\n\n")

for mod_name, mod_funcs in modules.items():
    with open(f'src/xmpp/split_output/{mod_name}.rs', 'w', encoding='utf-8') as f:
        f.write("use super::{ProtocolSession, Action};\n")
        f.write("use super::constants::*;\n")
        f.write("use super::xml_util::*;\n")
        f.write("use anyhow::Result;\n")
        f.write("use roxmltree::Node;\n\n")
        f.write("impl ProtocolSession {\n")
        for name in mod_funcs:
            if name in impl_funcs:
                f.write("    " + impl_funcs[name].replace('\n', '\n    ') + "\n\n")
        f.write("}\n")

with open('src/xmpp/split_output/protocol_new.rs', 'w', encoding='utf-8') as f:
    f.write(before_impl)
    f.write("\nimpl ProtocolSession {\n")
    for name in unmapped_impl:
        if name in impl_funcs:
            f.write("    " + impl_funcs[name].replace('\n', '\n    ') + "\n\n")
    f.write("}\n")
    
print("Done extracting!")
