-- Complete the optional MIX family profiles implemented by Northstar:
-- XEP-0404 (MIX-ANON), XEP-0407 (MIX-MISC), and the configurable
-- XEP-0406 rights which those profiles depend on.

ALTER TABLE mix_channels
    DROP CONSTRAINT mix_channels_jid_visibility_check,
    ADD CONSTRAINT mix_channels_jid_visibility_check
        CHECK (jid_visibility IN ('visible', 'maybe', 'hidden')),
    ADD COLUMN discoverable BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN allow_private_messages BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN allow_participant_invites BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN allow_user_message_retraction BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN administrator_retraction_rights VARCHAR(16) NOT NULL DEFAULT 'owners'
        CHECK (administrator_retraction_rights IN ('nobody', 'administrators', 'owners')),
    ADD COLUMN enforce_registered_nick BOOLEAN NOT NULL DEFAULT FALSE;

-- XEP-0404 preferences are per participant, persist while the participant is
-- joined, and disappear atomically with that participation.
CREATE TABLE mix_participant_preferences (
    channel_id UUID NOT NULL,
    participant_id UUID NOT NULL,
    jid_visibility VARCHAR(16) NOT NULL DEFAULT 'default'
        CHECK (jid_visibility IN ('default', 'never', 'always', 'prefer not')),
    private_messages VARCHAR(8) NOT NULL DEFAULT 'allow'
        CHECK (private_messages IN ('allow', 'block')),
    vcard VARCHAR(8) NOT NULL DEFAULT 'block'
        CHECK (vcard IN ('allow', 'block')),
    share_presence BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, participant_id),
    FOREIGN KEY (channel_id, participant_id)
        REFERENCES mix_participants(channel_id, participant_id) ON DELETE CASCADE
);

-- XEP-0407 service-wide nick registration.  Both a user and a nickname are
-- unique within a MIX service, so concurrent requests cannot steal a nick.
CREATE TABLE mix_registered_nicks (
    service_domain VARCHAR(1023) NOT NULL,
    jid VARCHAR(3071) NOT NULL,
    nick VARCHAR(1023) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (service_domain, jid),
    UNIQUE (service_domain, nick),
    CHECK (service_domain = lower(service_domain)),
    CHECK (jid = lower(jid) AND position('@' IN jid) > 1 AND position('/' IN jid) = 0),
    CHECK (octet_length(nick) BETWEEN 1 AND 1023)
);

-- Invitation tokens are stored only as SHA-256 digests.  Consumption and
-- allow-list admission happen in the same serializable transaction as join.
CREATE TABLE mix_invitations (
    id UUID PRIMARY KEY,
    channel_id UUID NOT NULL REFERENCES mix_channels(id) ON DELETE CASCADE,
    inviter_jid VARCHAR(3071) NOT NULL,
    invitee_jid VARCHAR(3071) NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (inviter_jid = lower(inviter_jid) AND position('@' IN inviter_jid) > 1 AND position('/' IN inviter_jid) = 0),
    CHECK (invitee_jid = lower(invitee_jid) AND position('@' IN invitee_jid) > 1 AND position('/' IN invitee_jid) = 0),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX mix_invitations_lookup_idx
    ON mix_invitations(channel_id, invitee_jid, expires_at)
    WHERE consumed_at IS NULL;

-- MIX-ANON JID map and MIX-MISC avatar nodes use the existing bounded event
-- store, with the same channel-level pruning and uniqueness guarantees.
ALTER TABLE mix_subscriptions DROP CONSTRAINT mix_subscriptions_node_check;
ALTER TABLE mix_subscriptions ADD CONSTRAINT mix_subscriptions_node_check CHECK (node IN (
    'urn:xmpp:mix:nodes:messages',
    'urn:xmpp:mix:nodes:presence',
    'urn:xmpp:mix:nodes:participants',
    'urn:xmpp:mix:nodes:info',
    'urn:xmpp:mix:nodes:config',
    'urn:xmpp:mix:nodes:allowed',
    'urn:xmpp:mix:nodes:banned',
    'urn:xmpp:mix:nodes:jidmap',
    'urn:xmpp:avatar:data',
    'urn:xmpp:avatar:metadata'
));

ALTER TABLE mix_pam_subscriptions DROP CONSTRAINT mix_pam_subscriptions_node_check;
ALTER TABLE mix_pam_subscriptions ADD CONSTRAINT mix_pam_subscriptions_node_check CHECK (node IN (
    'urn:xmpp:mix:nodes:messages',
    'urn:xmpp:mix:nodes:presence',
    'urn:xmpp:mix:nodes:participants',
    'urn:xmpp:mix:nodes:info',
    'urn:xmpp:avatar:data',
    'urn:xmpp:avatar:metadata'
));

ALTER TABLE mix_events DROP CONSTRAINT mix_events_node_check;
ALTER TABLE mix_events ADD CONSTRAINT mix_events_node_check CHECK (node IN (
    'urn:xmpp:mix:nodes:messages',
    'urn:xmpp:mix:nodes:presence',
    'urn:xmpp:mix:nodes:participants',
    'urn:xmpp:mix:nodes:info',
    'urn:xmpp:mix:nodes:config',
    'urn:xmpp:mix:nodes:allowed',
    'urn:xmpp:mix:nodes:banned',
    'urn:xmpp:mix:nodes:jidmap',
    'urn:xmpp:avatar:data',
    'urn:xmpp:avatar:metadata'
));

-- The public presence item identifier contains an opaque resource in hidden
-- and maybe-visible channels.  Keep the real publishing full JID in a
-- server-private column so unavailable presence and mediated IQs can resolve
-- it without exposing it in the PubSub item id or payload.
ALTER TABLE mix_events
    ADD COLUMN source_full_jid VARCHAR(4095);

ALTER TABLE mix_events
    ADD CONSTRAINT mix_events_source_full_jid_check CHECK (
        source_full_jid IS NULL OR (
            position('@' IN source_full_jid) > 1
            AND position('/' IN source_full_jid) > position('@' IN source_full_jid)
        )
    );

CREATE UNIQUE INDEX mix_presence_source_full_jid_idx
    ON mix_events(channel_id, node, source_full_jid)
    WHERE node = 'urn:xmpp:mix:nodes:presence' AND source_full_jid IS NOT NULL;
