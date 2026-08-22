CREATE INDEX audit_log_actor_idx ON audit_log(actor_id);
CREATE INDEX muc_rooms_owner_idx ON muc_rooms(owner_id);
CREATE INDEX muc_affiliations_user_idx ON muc_affiliations(user_id);
CREATE INDEX upload_slots_user_idx ON upload_slots(user_id);
CREATE INDEX invitation_tokens_created_by_idx ON invitation_tokens(created_by);
CREATE INDEX abuse_reports_assigned_admin_idx ON abuse_reports(assigned_admin_id);
CREATE INDEX abuse_appeals_appellant_idx ON abuse_appeals(appellant_id);
CREATE INDEX abuse_appeals_assigned_admin_idx ON abuse_appeals(assigned_admin_id);
