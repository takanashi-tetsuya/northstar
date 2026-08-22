pub fn take_frame(buffer: &mut String) -> Option<String> {
    let trimmed = buffer.trim_start();
    if trimmed.len() != buffer.len() {
        buffer.drain(..buffer.len() - trimmed.len());
    }
    if buffer.is_empty() {
        return None;
    }
    if buffer.starts_with("<?xml") {
        let end = buffer.find("?>")? + 2;
        buffer.drain(..end);
        return take_frame(buffer);
    }
    if buffer.starts_with("<stream:stream") || buffer.starts_with("<open") {
        let end = buffer.find('>')? + 1;
        return Some(buffer.drain(..end).collect());
    }
    if buffer.starts_with("</stream:stream") || buffer.starts_with("<close") {
        let end = buffer.find('>')? + 1;
        return Some(buffer.drain(..end).collect());
    }
    if !buffer.starts_with('<') {
        buffer.clear();
        return None;
    }
    let tag_end = buffer.find(|c: char| c == '>' || c.is_whitespace())?;
    let qualified = &buffer[1..tag_end];
    let close = format!("</{qualified}>");
    if let Some(end) = buffer.find(&close) {
        let frame_end = end + close.len();
        return Some(buffer.drain(..frame_end).collect());
    }
    let open_end = buffer.find('>')?;
    if buffer[..=open_end]
        .trim_end_matches('>')
        .trim_end()
        .ends_with('/')
    {
        return Some(buffer.drain(..=open_end).collect());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_stream_and_stanzas() {
        let mut data =
            "<stream:stream to='localhost'><message to='a@localhost'><body>hi</body></message>"
                .to_owned();
        assert!(take_frame(&mut data).unwrap().starts_with("<stream:stream"));
        assert_eq!(
            take_frame(&mut data).unwrap(),
            "<message to='a@localhost'><body>hi</body></message>"
        );
    }
}
