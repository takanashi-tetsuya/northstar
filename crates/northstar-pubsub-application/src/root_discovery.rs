//! Read-only PubSub root discovery and RSM page projection.

use crate::PubSubRootDiscoveryQueryRepository;
use anyhow::{anyhow, Result};
use northstar_pubsub_core::{PubSubRootDiscoNode, PubSubRootDiscoPage};

/// The wire parser supplies the optional RSM controls; the repository owns
/// visibility, cursor admission and the consistent count/page snapshot.
pub struct PubSubRootDiscoQuery<'a> {
    pub requester: &'a str,
    pub cursor: Option<&'a str>,
    pub backwards: bool,
    pub max: Option<usize>,
    pub rsm_requested: bool,
}

pub struct PubSubRootDiscoResult {
    pub nodes: Vec<PubSubRootDiscoNode>,
    pub total: usize,
    pub first_index: usize,
    pub include_rsm: bool,
}

/// A missing cursor is a normal XEP-0059 item-not-found outcome. The
/// transport adapter maps it to a stanza error and renders the returned page.
pub async fn discover_roots<R: PubSubRootDiscoveryQueryRepository>(
    repository: &R,
    query: PubSubRootDiscoQuery<'_>,
) -> Result<Option<PubSubRootDiscoResult>> {
    let limit = query.max.unwrap_or(100).min(1_000) as i64;
    let page = repository
        .root_disco_page(query.requester, query.cursor, query.backwards, limit)
        .await?;
    project_root_page(page, query.backwards, query.rsm_requested)
}

fn project_root_page(
    mut page: PubSubRootDiscoPage,
    backwards: bool,
    rsm_requested: bool,
) -> Result<Option<PubSubRootDiscoResult>> {
    if !page.cursor_exists {
        return Ok(None);
    }
    let total = usize::try_from(page.total)
        .map_err(|_| anyhow!("visible PubSub root count exceeded platform bounds"))?;
    if backwards {
        page.nodes.reverse();
    }
    let first_index = match page.nodes.first() {
        Some(first) => usize::try_from(first.index)
            .map_err(|_| anyhow!("visible PubSub root index exceeded platform bounds"))?,
        None => 0,
    };
    let include_rsm = rsm_requested || page.nodes.len() < total;
    Ok(Some(PubSubRootDiscoResult {
        nodes: page.nodes,
        total,
        first_index,
        include_rsm,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RootQuerySpy {
        limits: Mutex<Vec<i64>>,
    }

    impl PubSubRootDiscoveryQueryRepository for RootQuerySpy {
        async fn root_disco_page(
            &self,
            _requester: &str,
            _cursor: Option<&str>,
            _backwards: bool,
            limit: i64,
        ) -> Result<PubSubRootDiscoPage> {
            self.limits.lock().unwrap().push(limit);
            Ok(PubSubRootDiscoPage {
                total: 0,
                cursor_exists: true,
                nodes: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn root_query_keeps_default_zero_and_upper_bound() {
        let repository = RootQuerySpy::default();
        for max in [None, Some(0), Some(usize::MAX)] {
            discover_roots(
                &repository,
                PubSubRootDiscoQuery {
                    requester: "alice@example.test",
                    cursor: None,
                    backwards: false,
                    max,
                    rsm_requested: max.is_some(),
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(*repository.limits.lock().unwrap(), [100, 0, 1_000]);
    }

    fn page(cursor_exists: bool) -> PubSubRootDiscoPage {
        PubSubRootDiscoPage {
            total: 4,
            cursor_exists,
            nodes: [("serverinfo", 3), ("gamma", 2)]
                .into_iter()
                .map(|(node, index)| PubSubRootDiscoNode {
                    node: node.to_owned(),
                    title: None,
                    index,
                })
                .collect(),
        }
    }

    #[test]
    fn reverse_page_restores_ascending_wire_order_and_first_index() {
        let result = project_root_page(page(true), true, true).unwrap().unwrap();
        assert_eq!(result.nodes[0].node, "gamma");
        assert_eq!(result.nodes[1].node, "serverinfo");
        assert_eq!(result.first_index, 2);
        assert_eq!(result.total, 4);
        assert!(result.include_rsm);
    }

    #[test]
    fn missing_cursor_and_unrequested_truncation_have_distinct_outcomes() {
        assert!(project_root_page(page(false), false, true)
            .unwrap()
            .is_none());
        let result = project_root_page(page(true), false, false)
            .unwrap()
            .unwrap();
        assert!(result.include_rsm);
        let complete = PubSubRootDiscoPage {
            total: 0,
            cursor_exists: true,
            nodes: Vec::new(),
        };
        let result = project_root_page(complete, false, false).unwrap().unwrap();
        assert_eq!(result.first_index, 0);
        assert!(!result.include_rsm);
    }

    #[test]
    fn invalid_database_counts_and_indices_are_errors() {
        let mut invalid = page(true);
        invalid.total = -1;
        assert!(project_root_page(invalid, false, true).is_err());
        let mut invalid = page(true);
        invalid.nodes[0].index = -1;
        assert!(project_root_page(invalid, false, true).is_err());
    }
}
