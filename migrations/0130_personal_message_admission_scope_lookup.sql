-- Stage 70: bounded durable-message-admission identity and account-deletion
-- lookup keys.
--
-- Admission scopes are canonical JIDs up to 3071 octets, so a raw B-tree
-- key is not safe for all schema-valid values. The former identity key placed
-- both scopes directly in one unique B-tree tuple and could therefore reject
-- an otherwise valid maximum-length JID before application-level admission
-- validation ran.
--
-- The fixed-width built-in MD5 expressions below are index discriminators,
-- never identity authority. The archive conflict path rechecks canonical
-- actor/target scopes, raw authority spelling, identity value, and payload
-- evidence exactly. A fingerprint collision can thus only fail the attempted
-- admission closed; it cannot turn one principal's message into another
-- principal's replay. Distinct domain separators make the actor and target
-- projections unambiguous and prevent reuse as another schema projection.

DROP INDEX personal_message_admission_identity_key;

CREATE UNIQUE INDEX personal_message_admission_identity_key
    ON personal_message_admissions
       (identity_kind,
        (pg_catalog.md5(
            'northstar:personal-admission-actor-scope:v1:'::pg_catalog.text
            || actor_scope::pg_catalog.text
        )),
        (pg_catalog.md5(
            'northstar:personal-admission-target-scope:v1:'::pg_catalog.text
            || target_scope::pg_catalog.text
        )),
        identity_digest);

CREATE INDEX personal_message_admission_actor_scope_lookup_idx
    ON personal_message_admissions
       ((pg_catalog.md5('northstar:personal-admission-scope:v1:' || actor_scope)), id);

CREATE INDEX personal_message_admission_target_scope_lookup_idx
    ON personal_message_admissions
       ((pg_catalog.md5('northstar:personal-admission-scope:v1:' || target_scope)), id);
