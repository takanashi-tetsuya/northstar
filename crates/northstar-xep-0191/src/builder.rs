//! Safe XEP-0191 payload builders.

use crate::model::{BlockPattern, BlockingCommand, BlockingMutation};

pub fn build_payload(command: &BlockingCommand) -> String {
    match command {
        BlockingCommand::GetBlocklist => "<blocklist xmlns='urn:xmpp:blocking'/>".to_owned(),
        BlockingCommand::Mutate(BlockingMutation::Block(items)) => build_items("block", items),
        BlockingCommand::Mutate(BlockingMutation::Unblock(items)) => build_items("unblock", items),
        BlockingCommand::Mutate(BlockingMutation::UnblockAll) => {
            "<unblock xmlns='urn:xmpp:blocking'/>".to_owned()
        }
    }
}

pub fn build_blocklist_result(items: &[BlockPattern]) -> String {
    build_items("blocklist", items)
}

fn build_items(name: &str, items: &[BlockPattern]) -> String {
    let mut xml = String::new();
    xml.push('<');
    xml.push_str(name);
    xml.push_str(" xmlns='urn:xmpp:blocking'>");
    for item in items {
        xml.push_str("<item jid='");
        escape(&mut xml, &item.jid().to_string());
        xml.push_str("'/>");
    }
    xml.push_str("</");
    xml.push_str(name);
    xml.push('>');
    xml
}

fn escape(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            other => output.push(other),
        }
    }
}
