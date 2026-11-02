s/^rust_xmpp_server:db::schema::tests::/northstar_postgres:schema::tests::/
s/^rust_xmpp_server:db::migration_preflight::tests::/northstar_postgres:migration_preflight::tests::/
s/^rust_xmpp_server:db::identity_migration::tests::/northstar_workflows:identity_migration::tests::/
s/^rust_xmpp_server:db::\(jid\|authorization\|push\|profile\|remaining\|session\)_identity::tests::/northstar_workflows:identity_migration::\1_identity::tests::/
s/^rust_xmpp_server:db::migration_upgrade_test::/northstar_workflows:identity_migration::migration_upgrade_test::/
