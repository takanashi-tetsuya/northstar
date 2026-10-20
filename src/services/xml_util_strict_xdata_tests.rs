use super::*;

#[test]
fn test_strict_xdata_submit() {
    let allowed = &["username", "password"];

    // Valid form
    let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><field var='username'><value>user1</value></field></x>";
    let doc = roxmltree::Document::parse(xml).unwrap();
    let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
    assert!(res.is_ok());

    // Adjacent text/CDATA nodes are concatenated, never silently
    // truncated to the first XML text node.
    let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><field var='username'><value>us<![CDATA[er1]]></value></field></x>";
    let doc = roxmltree::Document::parse(xml).unwrap();
    let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
    assert_eq!(
        res.unwrap().get("username").map(String::as_str),
        Some("user1")
    );

    // Wrong FORM_TYPE
    let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>wrong</value></field><field var='username'><value>user1</value></field></x>";
    let doc = roxmltree::Document::parse(xml).unwrap();
    let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
    assert!(res.is_err());

    // Multivalue
    let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><field var='username'><value>user1</value><value>user2</value></field></x>";
    let doc = roxmltree::Document::parse(xml).unwrap();
    let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
    assert!(res.is_err());

    // Duplicate field
    let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><field var='username'><value>user1</value></field><field var='username'><value>user2</value></field></x>";
    let doc = roxmltree::Document::parse(xml).unwrap();
    let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
    assert!(res.is_err());

    // XEP-0004 requires unknown submitted fields to be ignored.
    let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><field var='unknown'><value>user1</value></field></x>";
    let doc = roxmltree::Document::parse(xml).unwrap();
    let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
    assert!(res.is_ok_and(|values| !values.contains_key("unknown")));

    // Mixed namespace
    let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><bad xmlns='other'/></x>";
    let doc = roxmltree::Document::parse(xml).unwrap();
    let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
    assert!(res.is_err());
}
