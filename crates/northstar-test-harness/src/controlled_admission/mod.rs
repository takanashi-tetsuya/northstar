//! Stage2 instance-owned controlled storage composition for the production
//! admission coordinator and locked-row decisions. No server, SQL, sockets,
//! listeners, wall clock, entropy source or process fault is used.
mod execution;
pub mod input;
mod stage1;
pub use execution::execute;
pub use input::{parse, Envelope, InputError};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn input() -> Value {
        let guard = json!({"account_bare":"a@example.test","normalized_target":"b@example.test","origin_id":"origin-1",
            "normalized_payload":"synthetic-payload","pow_intent_payload":"synthetic-intent","subject":"synthetic-subject",
            "actors":["user:actor-a"],"proof":null,"allowed":true,"actor_sequence_delta":1});
        let completion = json!({"operation_uuid":"10000000-0000-0000-0000-000000000001","effect_number":1,"generation":0,"attempt":1,
            "action":"reserve","actor":"actor-a","key":"key-a","payload_tag":"payload-a","lease":"lease-a","guard":guard,"reconcile_of":null});
        json!({"schema":input::INPUT_SCHEMA,"model":input::MODEL,"adapter":"controlled_rust","binding_version":"synthetic-material-v1",
            "scenario_id":"rust-controlled-unit","scope":"reservation_finalization_only",
            "initial":{"rows":[],"actor_sequences":{"actor-a":0},"proofs":[]},
            "bindings":{"actors":[{"label":"actor-a","uuid":"20000000-0000-0000-0000-000000000001"}],
                "keys":[{"label":"key-a","key_id":"synthetic-key","hex":"01".repeat(32)}],
                "payloads":[{"label":"payload-a","hex":"02".repeat(32)}],
                "leases":[{"label":"lease-a","uuid":"30000000-0000-0000-0000-000000000001"}]},
            "commands":[{"operation_id":"operation-1","operation_uuid":"10000000-0000-0000-0000-000000000001","effect_id":"effect-1","effect_number":1,
                "causal_id":null,"attempt":1,"generation":0,"action":"reserve","kind":"direct","actor":"actor-a","key":"key-a","payload_tag":"payload-a","lease":"lease-a",
                "candidates":["key-a"],"times":{"admission_us":1,"actor_policy_us":2,"finalize_us":3,"reconcile_us":4},"guard":guard,
                "schedule":{"cut":"none","world_commit":true,"cleanup":"bounded_skip_locked","locked_keys":[],"completions":[completion]},"reconcile_of":null}],
            "budgets":{"steps":256,"events":4096,"evidence_bytes":8388608},"stage1":null})
    }
    fn run(v: &Value) -> Value {
        let (e, hash) = parse(&serde_json::to_vec(v).unwrap()).unwrap();
        execute(&e, &hash).unwrap()
    }
    #[test]
    fn concrete_saved_completion_rejects_full_guard_mismatch_then_accepts_once() {
        let mut v = input();
        let valid = v["commands"][0]["schedule"]["completions"][0].clone();
        let mut wrong = valid.clone();
        wrong["guard"]["pow_intent_payload"] = "different-synthetic-intent".into();
        v["commands"][0]["schedule"]["completions"] = json!([wrong, valid.clone(), valid]);
        let out = run(&v);
        let p = &out["projection"][0];
        assert_eq!(p["domain"], "Proceed");
        assert_eq!(p["knowledge"], "ReceiptKnown");
        assert_eq!(
            p["completion"]["rejections"],
            json!([
            {"index":0,"reason":"Request","pending_preserved":true,"receipt_preserved":true},
            {"index":2,"reason":"AlreadyCompleted","pending_preserved":true,"receipt_preserved":true}])
        );
        assert_eq!(p["completion"]["pending"], false);
        assert_eq!(p["world"]["active"], 1);
    }
    #[test]
    fn returned_unknown_and_cancelled_commit_have_distinct_coordinator_observations() {
        let mut v = input();
        v["commands"][0]["schedule"]["cut"] = "commit_unknown".into();
        let returned = run(&v);
        assert_eq!(returned["projection"][0]["completion"]["accepted"], true);
        v["commands"][0]["schedule"]["cut"] = "commit_cancel".into();
        v["commands"][0]["schedule"]["completions"] = json!([]);
        let cancelled = run(&v);
        let p = &cancelled["projection"][0];
        assert_eq!(p["completion"]["accepted"], false);
        assert_eq!(p["completion"]["pending"], true);
        assert_eq!(p["world"]["active"], 1);
        assert_eq!(p["caller"]["active_min"], 0);
        assert_eq!(p["caller"]["active_max"], 1);
        assert_eq!(p["caller"]["reservation_receipt"], false);
        assert_eq!(cancelled["execution"], "Cancelled");
    }
    #[test]
    fn receipt_before_cancellation_is_preserved_without_caller_completion() {
        let mut v = input();
        v["commands"][0]["schedule"]["cut"] = "receipt_before_cancel".into();
        v["commands"][0]["schedule"]["completions"] = json!([]);
        let out = run(&v);
        let p = &out["projection"][0];
        assert_eq!(p["knowledge"], "ReceiptKnown");
        assert_eq!(p["caller"]["reservation_receipt"], true);
        assert_eq!(p["completion"]["accepted"], false);
        assert_eq!(p["completion"]["pending"], true);
    }
    #[test]
    fn no_valid_saved_completion_never_qualifies_terminal() {
        let mut v = input();
        v["commands"][0]["schedule"]["completions"][0]["attempt"] = 2.into();
        let out = run(&v);
        assert_eq!(out["execution"], "Inconclusive");
        assert_eq!(out["terminal"], false);
        assert_eq!(out["projection"][0]["caller"]["reservation_receipt"], true);
    }
    #[test]
    fn rejected_finalize_preserves_original_receipt_without_authorizing_changed_fence() {
        let mut v = input();
        v["bindings"]["leases"]
            .as_array_mut()
            .unwrap()
            .push(json!({"label":"wrong-lease","uuid":"30000000-0000-0000-0000-000000000002"}));
        let mut finalize = v["commands"][0].clone();
        finalize["operation_id"] = "operation-2".into();
        finalize["effect_id"] = "effect-2".into();
        finalize["operation_uuid"] = "10000000-0000-0000-0000-000000000002".into();
        finalize["effect_number"] = 2.into();
        finalize["causal_id"] = "operation-1".into();
        finalize["action"] = "finalize".into();
        finalize["lease"] = "wrong-lease".into();
        for key in ["operation_uuid", "effect_number", "action", "lease"] {
            finalize["schedule"]["completions"][0][key] = finalize[key].clone();
        }
        v["commands"].as_array_mut().unwrap().push(finalize);
        let out = run(&v);
        assert_eq!(out["projection"][1]["domain"], "LeaseLost");
        assert_eq!(
            out["projection"][1]["caller"]["reservation"],
            json!({
            "operation_id":"operation-1","effect_id":"effect-1","key":"key-a","payload_tag":"payload-a","lease":"lease-a","applies_to_command":false})
        );
        assert_eq!(
            out["projection"][1]["caller"]["finalization_receipt"],
            false
        );
    }
    #[test]
    fn parser_rejects_unknown_fields_and_duplicate_nested_maps() {
        let mut v = input();
        v["commands"][0]["guard"]["unexpected"] = "rejected".into();
        assert!(matches!(
            parse(&serde_json::to_vec(&v).unwrap()),
            Err(InputError::Fields)
        ));
        let text = serde_json::to_string(&input())
            .unwrap()
            .replace("\"actor-a\":0", "\"actor-a\":0,\"actor-a\":1");
        assert!(matches!(parse(text.as_bytes()), Err(InputError::Json)));
    }
    #[test]
    fn parser_requires_explicit_null_fields_in_every_saved_request() {
        for path in [
            vec!["stage1"],
            vec!["commands", "0", "causal_id"],
            vec!["commands", "0", "guard", "proof"],
            vec!["commands", "0", "guard", "origin_id"],
            vec!["commands", "0", "reconcile_of"],
            vec![
                "commands",
                "0",
                "schedule",
                "completions",
                "0",
                "reconcile_of",
            ],
        ] {
            let mut v = input();
            let mut target = &mut v;
            for part in &path[..path.len() - 1] {
                target = if let Ok(index) = part.parse::<usize>() {
                    &mut target[index]
                } else {
                    &mut target[*part]
                };
            }
            target
                .as_object_mut()
                .unwrap()
                .remove(path.last().unwrap().to_owned());
            assert!(matches!(
                parse(&serde_json::to_vec(&v).unwrap()),
                Err(InputError::Fields)
            ));
        }
    }
    #[test]
    fn budget_exhaustion_preserves_bounded_prefix_and_inconclusive() {
        let mut v = input();
        v["budgets"]["events"] = 1.into();
        let out = run(&v);
        assert_eq!(out["execution"], "Inconclusive");
        assert_eq!(out["evidence_complete"], false);
        assert_eq!(out["projection"], json!([]));
    }
}
