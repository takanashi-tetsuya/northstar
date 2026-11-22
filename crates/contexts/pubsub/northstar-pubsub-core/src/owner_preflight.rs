use crate::PubSubNode;

/// Node identity, requester ownership and optional graph from one snapshot.
#[derive(Clone, Debug)]
pub struct PubSubOwnerPreflight {
    pub node: PubSubNode,
    pub is_owner: bool,
    pub parents: Vec<String>,
    pub children: Vec<String>,
}
