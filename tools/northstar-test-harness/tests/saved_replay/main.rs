//! Saved replay tests: the Stage 4 and direct saved-case replay harnesses, the production-owner capture
//! adapters they drive and their ordinary controls. They wire several contexts' crates together through
//! supplied ports and need nothing from the composition root, so they moved here from the root crate in S41
//! with their module layout unchanged: test names keep their old paths (`stage4_replay::...`,
//! `xmpp::protocol::...`), including the two ignored saved-case entries the frozen Stage 4 tools selected by
//! name.

mod direct_replay;
mod stage4_replay;
mod xmpp;
