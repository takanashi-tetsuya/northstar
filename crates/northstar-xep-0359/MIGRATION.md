# Migration ledger: `northstar-xep-0359`

## Scope

This crate extracts the capability-free portion of XEP-0359 Unique and Stable
Stanza IDs: bounded direct-child parsing, canonical assigning-entity identity,
safe XML fragments, deduplication key types and the assigning entity's
replacement/delete decision.

## Legacy mapping

| Legacy location | Extracted responsibility |
| --- | --- |
| `src/xmpp/xml_util.rs::validate_stanza_ids` | `wire::parse_message` and strict element parsers |
| `src/xmpp/xml_util.rs::add_stanza_id` | `builder::build_stanza_id` plus `policy::plan_authority_update` |
| `src/xmpp/xml_util.rs::strip_stanza_ids_by_domain` | server adapter selects the canonical assigning entity and applies the typed authority plan |
| `src/abuse.rs` origin identity material | `DeduplicationKey::Origin`; hashing and persistent replay admission remain server authorities |
| archive/MUC/MIX/S2S stable IDs | `DeduplicationKey::Authoritative`; UUID allocation and durable projection remain application-service authorities |

## Authority boundary

The crate does not generate IDs, inspect clocks or randomness, authenticate
routes, query service discovery, store replay identities, open transactions,
mutate an archive, route a stanza or perform XML range editing. The caller must
provide a canonical authenticated assigning entity and an already generated
opaque ID. The messaging or room application service applies the returned plan
with the shared XML builder inside its complete transaction.

An `origin-id` is always treated as spoofable outside the caller's authenticated
sender scope. A `stanza-id` becomes suitable for trusted references only after
the caller verifies the assigning entity and its XEP-0359 discovery claim.

## Intentional differences from the legacy model

- Assigning entities are represented by `CanonicalJid`, not repeatedly
  canonicalized strings.
- Deduplication keys encode whether an ID is sender-scoped or entity-issued;
  an origin ID can never collide with a stanza ID merely because the text is
  equal.
- The direct SID child count is capped at 256 in addition to the server's
  stanza-byte limit.
- Unknown direct children in `urn:xmpp:sid:0` are counted but otherwise left
  for the routing adapter to preserve, matching the XEP's forward-compatible
  non-stripping rule.

## Integration steps

1. Remove the temporary crate-local `[workspace]` and add the crate to the root
   workspace.
2. Replace `validate_stanza_ids` with `parse_message` and map `SidError` to the
   existing stanza error vocabulary.
3. Replace local account/room issuer comparison with `CanonicalJid` and
   `plan_authority_update`.
4. Apply removal and safe fragment insertion through the shared typed XML
   builder; preserve foreign IDs, unknown SID children and the origin ID.
5. Move origin/account/room/S2S deduplication inputs to the typed key variants
   without moving SQL or transaction ownership into this crate.
6. Remove the duplicate root validators only after C2S, MAM, MUC, MIX, S2S and
   cluster replay tests pass.
