#[cfg(test)]
mod health_regressions {
    use super::super::*;

    #[test]
    fn process_roles_have_explicit_non_overlapping_retention_ownership() {
        assert!(ProcessRole::parse(&[]).unwrap().embeds_retention());
        assert!(ProcessRole::parse(&["serve".into(), "standalone".into()])
            .unwrap()
            .embeds_retention());
        for role in ["core", "maintenance"] {
            assert!(!ProcessRole::parse(&["serve".into(), role.into()])
                .unwrap()
                .embeds_retention());
        }
        for args in [
            vec!["serve"],
            vec!["serve", "worker"],
            vec!["serve", "core", "extra"],
            vec!["typo"],
        ] {
            assert!(
                ProcessRole::parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>())
                    .is_err()
            );
        }
    }

    #[test]
    fn split_process_budget_includes_all_physical_runtime_role_connections() {
        let budget = northstar_config::runtime_connection_budget_manifest();
        assert_eq!(
            MAX_CORE_PRIMARY_CONNECTIONS
                + MAINTENANCE_POOL_MAX_CONNECTIONS
                + budget.auxiliary_connections,
            budget.runtime_role_connection_limit
        );
        assert!(MAX_CORE_PRIMARY_CONNECTIONS >= budget.primary_pool_min_connections);
    }
}
