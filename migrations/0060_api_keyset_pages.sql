-- Global users, invitations, reports and MUC indexes were added by 0057.
-- Message archive keysets are already covered by 0031's
-- (owner_id,created_at,id) and 0042's (owner_id,peer_jid,created_at,id). A
-- PostgreSQL B-tree can scan those indexes backward for the all-DESC order;
-- do not build duplicate blocking indexes on the largest table.
CREATE INDEX abuse_reports_api_reporter_page_idx
    ON abuse_reports (reporter_id, created_at DESC, id DESC);
CREATE INDEX abuse_reports_api_reporter_status_page_idx
    ON abuse_reports (reporter_id, status, created_at DESC, id DESC);
