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
    use northstar_abuse_policy::{admission_execution as core, admission_transaction as tx};
    use serde_json::{json, Value};
    pub(super) fn input() -> Value {
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
    pub(super) fn reconcile_input() -> Value {
        let mut v = input();
        v["commands"][0]["schedule"]["cut"] = "commit_unknown".into();
        let mut reconcile = v["commands"][0].clone();
        reconcile["operation_id"] = "operation-2".into();
        reconcile["effect_id"] = "effect-2".into();
        reconcile["operation_uuid"] = "10000000-0000-0000-0000-000000000002".into();
        reconcile["effect_number"] = 2.into();
        reconcile["action"] = "reconcile".into();
        reconcile["reconcile_of"] = "operation-1".into();
        reconcile["schedule"]["cut"] = "none".into();
        refresh_completion(&mut reconcile);
        v["commands"].as_array_mut().unwrap().push(reconcile);
        v
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
        assert_eq!(p["coordinator"]["state"], "Finished");
        assert_eq!(p["coordinator"]["outcome"], "Completed");
        assert_eq!(p["coordinator"]["result"]["kind"], "Begin.Reserved");
        assert_eq!(p["coordinator"]["knowledge"], p["witness"]);
        assert_eq!(out["coordinators_finished"], true);
        assert_eq!(p["world"]["active"], 1);
    }
    #[test]
    fn returned_unknown_and_cancelled_commit_have_distinct_coordinator_observations() {
        let mut v = input();
        v["commands"][0]["schedule"]["cut"] = "commit_unknown".into();
        let returned = run(&v);
        assert_eq!(returned["projection"][0]["completion"]["accepted"], true);
        assert_eq!(
            returned["projection"][0]["coordinator"]["outcome"],
            "Unknown"
        );
        assert_eq!(returned["projection"][0]["coordinator"]["cause"], "Backend");
        assert_eq!(returned["projection"][0]["cancellation"], false);
        assert_eq!(returned["coordinators_finished"], true);
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
        assert_eq!(p["domain"], "AwaitingCompletion");
        assert_eq!(
            p["coordinator"],
            json!({"state":"Waiting","outcome":null,"result":null,"cause":null,"knowledge":null})
        );
        assert_eq!(p["witness"]["kind"], "CommitCallEntered");
        assert_eq!(p["witness"]["fact"]["kind"], "Reserved");
        assert_eq!(p["cancellation"], true);
        assert_eq!(cancelled["execution"], "Cancelled");
        assert_eq!(cancelled["terminal"], true);
        assert_eq!(cancelled["coordinators_finished"], false);
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
        assert_eq!(p["domain"], "AwaitingCompletion");
        assert_eq!(p["coordinator"]["outcome"], Value::Null);
        assert_eq!(p["witness"]["fact"]["fence"]["lease"], "lease-a");
        assert_eq!(out["execution"], "Cancelled");
        assert_eq!(out["coordinators_finished"], false);
    }
    #[test]
    fn no_valid_saved_completion_never_qualifies_terminal() {
        let mut v = input();
        v["commands"][0]["schedule"]["completions"][0]["attempt"] = 2.into();
        let out = run(&v);
        assert_eq!(out["execution"], "Inconclusive");
        assert_eq!(out["terminal"], false);
        assert_eq!(out["projection"][0]["caller"]["reservation_receipt"], true);
        assert_eq!(out["projection"][0]["coordinator"]["state"], "Waiting");
        assert_eq!(out["projection"][0]["execution"], "Inconclusive");
        assert_eq!(out["coordinators_finished"], false);
    }
    #[test]
    fn undelivered_failure_does_not_manufacture_an_outcome_from_the_cut() {
        for cut in ["commit_unknown", "precommit_error"] {
            let mut v = input();
            v["commands"][0]["schedule"]["cut"] = cut.into();
            v["commands"][0]["schedule"]["world_commit"] = (cut == "commit_unknown").into();
            v["commands"][0]["schedule"]["completions"][0]["attempt"] = 2.into();
            let out = run(&v);
            let event = &out["projection"][0];
            assert_eq!(event["domain"], "AwaitingCompletion");
            assert_eq!(event["coordinator"]["outcome"], Value::Null);
            assert_eq!(event["cancellation"], false);
            assert_eq!(out["execution"], "Inconclusive");
            assert_eq!(event["caller"]["unresolved"], cut == "commit_unknown");
            if cut == "commit_unknown" {
                assert_eq!(event["witness"]["fact"]["kind"], "Reserved");
            }
        }
    }
    fn retained_receipt(e: &Envelope) -> core::Receipt {
        let c = &e.commands[0];
        core::Receipt {
            correlation: core::Correlation {
                operation: c.operation_uuid,
                effect: c.effect_number,
                generation: c.generation,
                attempt: c.attempt,
            },
            scope: core::TransactionScope::RatedBegin(core::BeginCommitPurpose::NewReservation),
            fact: core::CommitFact::Reserved(tx::AdmissionFence {
                admission_key: input::bytes32(&e.key(&c.key).hex).unwrap().to_vec(),
                payload_mac: e.payload(&c.payload_tag),
                lease_token: e.lease(&c.lease),
            }),
        }
    }
    #[test]
    fn projection_observes_altered_core_classification_instead_of_saved_cut() {
        let (e, _) = parse(&serde_json::to_vec(&input()).unwrap()).unwrap();
        let receipt = retained_receipt(&e);
        let core::CommitFact::Reserved(fence) = &receipt.fact else {
            panic!("reservation fixture")
        };
        let completed = core::ExecutionState::Finished(core::ExecutionOutcome::Completed {
            result: core::EffectResult::Begin(core::BeginResult::Reserved(fence.clone())),
            knowledge: core::Knowledge::ReceiptKnown(receipt.clone()),
        });
        let preserved = core::ExecutionState::Finished(core::ExecutionOutcome::ReceiptPreserved {
            receipt: receipt.clone(),
            cause: core::FailureKind::Cancelled,
        });
        let unknown = core::ExecutionState::Finished(core::ExecutionOutcome::Unknown {
            prepared: core::PreparedCommit {
                correlation: receipt.correlation,
                scope: receipt.scope,
                fact: receipt.fact,
            },
            cause: core::FailureKind::Backend,
        });
        for (state, domain, outcome, knowledge) in [
            (completed, "Proceed", "Completed", "ReceiptKnown"),
            (
                preserved,
                "ReceiptPreserved",
                "ReceiptPreserved",
                "ReceiptKnown",
            ),
            (unknown, "Unknown", "Unknown", "CommitCallEntered"),
        ] {
            // All three consume the identical input whose cut is "none".
            let observed = execution::coordinator_projection(&e, &state);
            assert_eq!(execution::coordinator_domain(&state), domain);
            assert_eq!(observed["outcome"], outcome);
            assert_eq!(observed["knowledge"]["kind"], knowledge);
            assert_eq!(observed["knowledge"]["fact"]["fence"]["key"], "key-a");
        }
    }
    #[test]
    fn actual_unbound_and_out_of_input_range_values_remain_observation_failures() {
        let (e, _) = parse(&serde_json::to_vec(&input()).unwrap()).unwrap();
        let mut receipt = retained_receipt(&e);
        receipt.correlation.operation = uuid::Uuid::from_u128(9);
        receipt.correlation.effect = 0;
        receipt.correlation.generation = u64::MAX;
        receipt.correlation.attempt = u32::MAX;
        let core::CommitFact::Reserved(fence) = &mut receipt.fact else {
            panic!("reservation fixture")
        };
        fence.admission_key = vec![0xff; 32];
        let state = core::ExecutionState::Finished(core::ExecutionOutcome::ReceiptPreserved {
            receipt,
            cause: core::FailureKind::Backend,
        });
        let observed = execution::coordinator_projection(&e, &state);
        assert_eq!(observed["knowledge"]["correlation"]["mapped"], false);
        assert_eq!(
            observed["knowledge"]["correlation"]["operation_id"],
            Value::Null
        );
        assert_eq!(observed["knowledge"]["correlation"]["effect_number"], 0);
        assert_eq!(observed["knowledge"]["correlation"]["generation"], u64::MAX);
        assert_eq!(observed["knowledge"]["fact"]["fence"]["mapped"], false);
        assert_eq!(observed["knowledge"]["fact"]["fence"]["key"], Value::Null);
    }
    #[test]
    fn stage1_cancel_translation_keeps_native_waiting_observation() {
        let mut v = input();
        v["commands"][0]["schedule"]["cut"] = "before_effect_cancel".into();
        v["commands"][0]["schedule"]["world_commit"] = false.into();
        v["commands"][0]["schedule"]["completions"] = json!([]);
        let (e, _) = parse(&serde_json::to_vec(&v).unwrap()).unwrap();
        let out = run(&v);
        let native = &out["projection"][0];
        assert_eq!(native["domain"], "AwaitingCompletion");
        assert_eq!(native["coordinator"]["state"], "Waiting");
        let legacy = stage1::projection(&e.commands[0], native);
        assert_eq!(legacy["domain"], "NotRequested");
        assert_eq!(legacy["execution"], "Cancelled");
    }
    #[test]
    fn rejected_reconcile_delivery_cannot_publish_repository_observation() {
        let mut v = reconcile_input();
        v["commands"][1]["schedule"]["completions"][0]["attempt"] = 2.into();
        let out = run(&v);
        assert_eq!(
            out["projection"][1]["world"]["result"],
            "ReconcileExactPending"
        );
        assert_eq!(out["projection"][1]["reconcile"], Value::Null);
        assert_eq!(out["projection"][1]["coordinator"]["outcome"], Value::Null);
        assert_eq!(out["execution"], "Inconclusive");
    }
    #[test]
    fn successive_reconcile_samples_keep_their_own_effect_and_unknown_target() {
        let mut v = reconcile_input();
        v["commands"][1]["times"]["reconcile_us"] = 10_000_001.into();
        let mut next = v["commands"][1].clone();
        next["operation_id"] = "operation-3".into();
        next["effect_id"] = "effect-3".into();
        next["operation_uuid"] = "10000000-0000-0000-0000-000000000003".into();
        next["effect_number"] = 3.into();
        next["generation"] = 5.into();
        next["attempt"] = 7.into();
        next["times"]["reconcile_us"] = 60_000_001.into();
        refresh_completion(&mut next);
        v["commands"].as_array_mut().unwrap().push(next);
        let out = run(&v);
        for (index, time, validity, generation, attempt) in [
            (1, 10_000_001, "Current", 0, 1),
            (2, 60_000_001, "Expired", 5, 7),
        ] {
            let event = &out["projection"][index];
            let returned = &event["coordinator"]["result"]["reconcile"];
            assert_eq!(returned["observed_at_us"], time);
            assert_eq!(returned["observed_at_source"], "Scripted");
            assert_eq!(returned["lease"], validity);
            assert_eq!(
                returned["correlation"],
                json!({"mapped":true,
                "operation_id":format!("operation-{}", index + 1),
                "effect_number":index + 1,"generation":generation,"attempt":attempt})
            );
            assert_eq!(
                returned["unresolved"],
                out["projection"][0]["witness"]["correlation"]
            );
            assert_eq!(
                returned["fence"],
                json!({"mapped":true,"key":"key-a","payload_tag":"payload-a","lease":"lease-a"})
            );
            assert_eq!(
                event["reconcile"]["observed_at_us"],
                returned["observed_at_us"]
            );
            assert_eq!(event["reconcile"]["unresolved_operation_preserved"], true);
            assert_eq!(event["witness"]["kind"], "NoCommitRequested");
            assert_eq!(event["caller"]["reservation_receipt"], false);
        }
        assert_eq!(out["projection"][0]["coordinator"]["outcome"], "Unknown");
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
    fn parser_rejects_complete_positional_root() {
        let mut value = input();
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_ok());
        make_positional_record(
            &mut value,
            &[
                "schema",
                "model",
                "adapter",
                "binding_version",
                "scenario_id",
                "scope",
                "initial",
                "bindings",
                "commands",
                "budgets",
                "stage1",
            ],
        );
        assert!(matches!(
            parse(&serde_json::to_vec(&value).unwrap()),
            Err(InputError::Fields)
        ));
    }

    fn make_positional_record(value: &mut Value, fields: &[&str]) {
        let object = value.as_object_mut().unwrap();
        assert_eq!(object.len(), fields.len());
        let positional = fields
            .iter()
            .map(|field| object.remove(*field).unwrap())
            .collect();
        *value = Value::Array(positional);
    }

    fn parser_input_with_optional_records() -> Value {
        let mut value = input();
        value["initial"]["rows"] = json!([{
            "actor":"actor-a","key":"key-a","payload_tag":"payload-a","state":"pending",
            "expires_at_us":20,"lease":"lease-a","lease_until_us":10
        }]);
        let proof = json!({
            "challenge_id":"abcdef00-0000-0000-0000-000000000001","nonce":"synthetic-nonce"
        });
        value["initial"]["proofs"] = json!([proof["challenge_id"]]);
        value["commands"][0]["guard"]["proof"] = proof.clone();
        value["commands"][0]["schedule"]["completions"][0]["guard"]["proof"] = proof;
        value
    }

    fn parser_stage1_input() -> Value {
        let mut value = input();
        let command = &mut value["commands"][0];
        command["generation"] = 1.into();
        command["times"] = json!({
            "admission_us":1,"actor_policy_us":1,"finalize_us":1,"reconcile_us":1
        });
        command["guard"]["actor_sequence_delta"] = 0.into();
        command["schedule"]["cleanup"] = "exact_key_only".into();
        refresh_completion(command);
        let scenario = json!({
            "schema":"northstar-admission-scenario-v1","model":"admission-fixture-v1",
            "scenario_id":"rust-controlled-unit","purpose":"normal",
            "policy":{"actor_capacity":4096,"accepted_ttl_us":21600000000_u64,
                "pending_ttl_us":1800000000,"lease_us":60000000},
            "clock":{"domain":"sql_model","unit":"microsecond","start_us":0},
            "actors":["actor-a"],"initial_rows":[],
            "commands":[{"operation_id":"operation-1","effect_id":"effect-1","causal_id":null,
                "attempt":1,"time_us":1,"action":"reserve","kind":"direct","actor":"actor-a",
                "key":"key-a","payload_tag":"payload-a","lease":"lease-a","cut":"none"}],
            "budgets":{"domain_us":10,"wall_ms":1,"steps":1,"events":1,
                "evidence_bytes":2048,"memory_bytes":4096,"files":0},
            "termination":{"after_commands":"complete","terminal_required":true},"seed":null
        });
        value["stage1"] = json!({"sha256":input::digest(&scenario),"scenario":scenario});
        value
    }

    #[test]
    fn parser_rejects_positional_nested_records() {
        let guard_fields: &[&str] = &[
            "account_bare",
            "normalized_target",
            "origin_id",
            "normalized_payload",
            "pow_intent_payload",
            "subject",
            "actors",
            "proof",
            "allowed",
            "actor_sequence_delta",
        ];
        let records: &[(&str, &[&str])] = &[
            ("/initial", &["rows", "actor_sequences", "proofs"]),
            (
                "/initial/rows/0",
                &[
                    "actor",
                    "key",
                    "payload_tag",
                    "state",
                    "expires_at_us",
                    "lease",
                    "lease_until_us",
                ],
            ),
            ("/bindings", &["actors", "keys", "payloads", "leases"]),
            ("/bindings/actors/0", &["label", "uuid"]),
            ("/bindings/keys/0", &["label", "key_id", "hex"]),
            ("/bindings/payloads/0", &["label", "hex"]),
            ("/bindings/leases/0", &["label", "uuid"]),
            (
                "/commands/0",
                &[
                    "operation_id",
                    "operation_uuid",
                    "effect_number",
                    "effect_id",
                    "causal_id",
                    "attempt",
                    "generation",
                    "action",
                    "kind",
                    "actor",
                    "key",
                    "payload_tag",
                    "lease",
                    "candidates",
                    "times",
                    "guard",
                    "schedule",
                    "reconcile_of",
                ],
            ),
            (
                "/commands/0/times",
                &[
                    "admission_us",
                    "actor_policy_us",
                    "finalize_us",
                    "reconcile_us",
                ],
            ),
            ("/commands/0/guard", guard_fields),
            ("/commands/0/guard/proof", &["challenge_id", "nonce"]),
            (
                "/commands/0/schedule",
                &[
                    "cut",
                    "world_commit",
                    "cleanup",
                    "locked_keys",
                    "completions",
                ],
            ),
            (
                "/commands/0/schedule/completions/0",
                &[
                    "operation_uuid",
                    "effect_number",
                    "generation",
                    "attempt",
                    "action",
                    "actor",
                    "key",
                    "payload_tag",
                    "lease",
                    "guard",
                    "reconcile_of",
                ],
            ),
            ("/commands/0/schedule/completions/0/guard", guard_fields),
            (
                "/commands/0/schedule/completions/0/guard/proof",
                &["challenge_id", "nonce"],
            ),
            ("/budgets", &["steps", "events", "evidence_bytes"]),
            ("/stage1", &["scenario", "sha256"]),
        ];
        for (path, fields) in records {
            let mut value = if *path == "/stage1" {
                parser_stage1_input()
            } else {
                parser_input_with_optional_records()
            };
            assert!(
                parse(&serde_json::to_vec(&value).unwrap()).is_ok(),
                "{path}"
            );
            make_positional_record(value.pointer_mut(path).unwrap(), fields);
            assert!(
                matches!(
                    parse(&serde_json::to_vec(&value).unwrap()),
                    Err(InputError::Fields)
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn parser_rejects_positional_stage1_bridge_records_after_digest_check() {
        let records: &[(&str, &[&str])] = &[
            (
                "",
                &[
                    "schema",
                    "model",
                    "scenario_id",
                    "purpose",
                    "policy",
                    "clock",
                    "actors",
                    "initial_rows",
                    "commands",
                    "budgets",
                    "termination",
                    "seed",
                ],
            ),
            (
                "/policy",
                &[
                    "actor_capacity",
                    "accepted_ttl_us",
                    "pending_ttl_us",
                    "lease_us",
                ],
            ),
            ("/clock", &["domain", "unit", "start_us"]),
            (
                "/commands/0",
                &[
                    "operation_id",
                    "effect_id",
                    "causal_id",
                    "attempt",
                    "time_us",
                    "action",
                    "kind",
                    "actor",
                    "key",
                    "payload_tag",
                    "lease",
                    "cut",
                ],
            ),
            (
                "/budgets",
                &[
                    "domain_us",
                    "wall_ms",
                    "steps",
                    "events",
                    "evidence_bytes",
                    "memory_bytes",
                    "files",
                ],
            ),
            ("/termination", &["after_commands", "terminal_required"]),
        ];
        for (path, fields) in records {
            let mut value = parser_stage1_input();
            assert!(parse(&serde_json::to_vec(&value).unwrap()).is_ok());
            make_positional_record(
                value["stage1"]["scenario"].pointer_mut(path).unwrap(),
                fields,
            );
            value["stage1"]["sha256"] = input::digest(&value["stage1"]["scenario"]).into();
            assert!(
                matches!(
                    parse(&serde_json::to_vec(&value).unwrap()),
                    Err(InputError::Stage1)
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn parser_rejects_array_hidden_uuid_aliases() {
        let canonical = "abcdef00-0000-0000-0000-000000000001";
        let aliases = [
            "ABCDEF00-0000-0000-0000-000000000001",
            "abcdef00000000000000000000000001",
            "{abcdef00-0000-0000-0000-000000000001}",
            "urn:uuid:abcdef00-0000-0000-0000-000000000001",
        ];
        for path in ["/bindings/actors/0", "/bindings/leases/0"] {
            let mut control = input();
            control.pointer_mut(path).unwrap()["uuid"] = canonical.into();
            assert!(parse(&serde_json::to_vec(&control).unwrap()).is_ok());
            for alias in aliases {
                assert_eq!(
                    uuid::Uuid::parse_str(alias).unwrap(),
                    uuid::Uuid::parse_str(canonical).unwrap()
                );
                let mut value = control.clone();
                let binding = value.pointer_mut(path).unwrap();
                binding["uuid"] = alias.into();
                make_positional_record(binding, &["label", "uuid"]);
                assert!(
                    matches!(
                        parse(&serde_json::to_vec(&value).unwrap()),
                        Err(InputError::Fields)
                    ),
                    "{path}: {alias}"
                );
            }
        }
    }

    #[test]
    fn parser_preserves_object_roundtrip_and_canonical_material() {
        let mut nulls = input();
        nulls["commands"][0]["guard"]["origin_id"] = Value::Null;
        nulls["commands"][0]["schedule"]["completions"][0]["guard"]["origin_id"] = Value::Null;
        for value in [
            input(),
            nulls,
            parser_input_with_optional_records(),
            parser_stage1_input(),
        ] {
            let (envelope, hash) = parse(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(serde_json::to_value(envelope).unwrap(), value);
            assert_eq!(hash, input::digest(&value));
        }
        for path in [
            "/bindings/actors/0/uuid",
            "/bindings/leases/0/uuid",
            "/commands/0/operation_uuid",
            "/commands/0/guard/proof/challenge_id",
            "/commands/0/schedule/completions/0/operation_uuid",
            "/commands/0/schedule/completions/0/guard/proof/challenge_id",
            "/initial/proofs/0",
        ] {
            let mut value = parser_input_with_optional_records();
            *value.pointer_mut(path).unwrap() = "abcdef00-0000-0000-0000-000000000001".into();
            assert!(
                parse(&serde_json::to_vec(&value).unwrap()).is_ok(),
                "{path}"
            );
            *value.pointer_mut(path).unwrap() = "ABCDEF00-0000-0000-0000-000000000001".into();
            assert!(
                matches!(
                    parse(&serde_json::to_vec(&value).unwrap()),
                    Err(InputError::Binding)
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn parser_rejects_unknown_fields_and_duplicate_nested_maps() {
        let mut v = input();
        v["commands"][0]["guard"]["unexpected"] = "rejected".into();
        assert!(matches!(
            parse(&serde_json::to_vec(&v).unwrap()),
            Err(InputError::Fields)
        ));
        for (value, field) in [
            (input(), "\"scenario_id\":\"rust-controlled-unit\""),
            (input(), "\"allowed\":true"),
            (input(), "\"actor-a\":0"),
            (parser_stage1_input(), "\"actor_capacity\":4096"),
        ] {
            let text = serde_json::to_string(&value).unwrap();
            assert!(text.contains(field));
            let text = text.replacen(field, &format!("{field},{field}"), 1);
            assert!(matches!(parse(text.as_bytes()), Err(InputError::Json)));
        }
        let mut bridge = parser_stage1_input();
        bridge["stage1"]["scenario"]["policy"]["unexpected"] = true.into();
        bridge["stage1"]["sha256"] = input::digest(&bridge["stage1"]["scenario"]).into();
        assert!(matches!(
            parse(&serde_json::to_vec(&bridge).unwrap()),
            Err(InputError::Stage1)
        ));
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
                "guard",
                "proof",
            ],
            vec![
                "commands",
                "0",
                "schedule",
                "completions",
                "0",
                "guard",
                "origin_id",
            ],
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
        for path in ["/seed", "/commands/0/causal_id"] {
            let mut value = parser_stage1_input();
            let (parent, field) = path.rsplit_once('/').unwrap();
            value["stage1"]["scenario"]
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            value["stage1"]["sha256"] = input::digest(&value["stage1"]["scenario"]).into();
            assert!(matches!(
                parse(&serde_json::to_vec(&value).unwrap()),
                Err(InputError::Stage1)
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
        assert_eq!(out["terminal"], false);
        assert_eq!(out["coordinators_finished"], false);
    }

    fn refresh_completion(c: &mut Value) {
        let fields = [
            "operation_uuid",
            "effect_number",
            "generation",
            "attempt",
            "action",
            "actor",
            "key",
            "payload_tag",
            "lease",
            "guard",
            "reconcile_of",
        ];
        let completion = fields
            .into_iter()
            .map(|key| (key.to_string(), c[key].clone()))
            .collect();
        c["schedule"]["completions"] = Value::Array(vec![Value::Object(completion)]);
    }
    fn independent_commands(count: usize, unknown: bool) -> Value {
        let mut v = input();
        let template = v["commands"][0].clone();
        let mut commands = Vec::new();
        let mut keys = Vec::new();
        for index in 1..=count {
            let key = format!("key-{index}");
            keys.push(json!({"label":key,"key_id":"synthetic-key","hex":format!("{index:02x}").repeat(32)}));
            let mut c = template.clone();
            c["key"] = key.clone().into();
            c["candidates"] = json!([key]);
            c["operation_id"] = format!("operation-{index}").into();
            c["effect_id"] = format!("effect-{index}").into();
            c["operation_uuid"] = format!("10000000-0000-0000-0000-{index:012}").into();
            c["effect_number"] = index.into();
            c["schedule"]["cut"] = if unknown { "commit_unknown" } else { "none" }.into();
            refresh_completion(&mut c);
            commands.push(c);
        }
        v["bindings"]["keys"] = keys.into();
        v["commands"] = commands.into();
        v
    }
    #[test]
    fn confirmed_later_reservation_preserves_both_earlier_unknown_worlds() {
        for committed in [false, true] {
            let mut v = independent_commands(2, false);
            v["commands"][0]["schedule"]["cut"] = "commit_unknown".into();
            v["commands"][0]["schedule"]["world_commit"] = committed.into();
            let out = run(&v);
            let caller = &out["projection"][1]["caller"];
            assert_eq!(caller["active_min"], 1);
            assert_eq!(caller["active_max"], 2);
            assert_eq!(caller["possible_states"], 2);
            assert_eq!(caller["knowledge_complete"], true);
            assert_eq!(out["projection"][0]["coordinator"]["outcome"], "Unknown");
            assert_eq!(out["projection"][1]["coordinator"]["outcome"], "Completed");
            assert_eq!(
                out["projection"][1]["world"]["active"],
                if committed { 2 } else { 1 }
            );
        }
    }
    #[test]
    fn independent_unknowns_keep_four_correlated_states_for_every_injected_world() {
        for mask in 0..4 {
            let mut v = independent_commands(2, true);
            for index in 0..2 {
                v["commands"][index]["schedule"]["world_commit"] =
                    (mask & (1 << index) != 0).into();
            }
            let out = run(&v);
            let caller = &out["projection"][1]["caller"];
            assert_eq!(caller["active_min"], 0);
            assert_eq!(caller["active_max"], 2);
            assert_eq!(caller["possible_states"], 4);
        }
    }
    #[test]
    fn no_commit_failure_or_cancellation_cannot_select_a_prior_view() {
        for cut in ["precommit_error", "before_effect_cancel"] {
            let mut v = independent_commands(2, true);
            v["commands"][1]["schedule"]["cut"] = cut.into();
            v["commands"][1]["schedule"]["world_commit"] = false.into();
            if cut == "before_effect_cancel" {
                v["commands"][1]["schedule"]["completions"] = json!([]);
            }
            let out = run(&v);
            let caller = &out["projection"][1]["caller"];
            assert_eq!(caller["active_min"], 0);
            assert_eq!(caller["active_max"], 1);
            assert_eq!(caller["possible_states"], 2);
        }
    }
    #[test]
    fn ttl_narrows_active_occupancy_without_erasing_retention_or_unknown_history() {
        let mut v = independent_commands(2, true);
        let c = &mut v["commands"][1];
        c["action"] = "guard_memory".into();
        c["schedule"]["cut"] = "none".into();
        c["times"] = json!({"admission_us":1_800_000_001i64,"actor_policy_us":1_800_000_001i64,
            "finalize_us":1_800_000_001i64,"reconcile_us":1_800_000_001i64});
        refresh_completion(c);
        let out = run(&v);
        let caller = &out["projection"][1]["caller"];
        assert_eq!(caller["active_min"], 0);
        assert_eq!(caller["active_max"], 0);
        assert_eq!(caller["retained_min"], 0);
        assert_eq!(caller["retained_max"], 1);
        assert_eq!(caller["possible_states"], 2);
        assert_eq!(out["projection"][0]["witness"]["kind"], "CommitCallEntered");
    }
    #[test]
    fn only_delivered_reconciliation_filters_current_views_and_never_rewrites_history() {
        for committed in [false, true] {
            for delivered in [false, true] {
                let mut v = independent_commands(2, true);
                v["commands"][0]["schedule"]["world_commit"] = committed.into();
                let c = &mut v["commands"][1];
                c["action"] = "reconcile".into();
                c["key"] = "key-1".into();
                c["candidates"] = json!(["key-1"]);
                c["reconcile_of"] = "operation-1".into();
                c["schedule"]["cut"] = "none".into();
                refresh_completion(c);
                if !delivered {
                    c["schedule"]["completions"][0]["attempt"] = 2.into();
                }
                let out = run(&v);
                let event = &out["projection"][1];
                assert_eq!(
                    event["caller"]["possible_states"],
                    if delivered { 1 } else { 2 }
                );
                assert_eq!(
                    event["caller"]["active_min"],
                    usize::from(delivered && committed)
                );
                assert_eq!(
                    event["caller"]["active_max"],
                    usize::from(!delivered || committed)
                );
                assert_eq!(out["projection"][0]["coordinator"]["outcome"], "Unknown");
                if delivered {
                    assert_eq!(event["reconcile"]["unresolved_operation_preserved"], true);
                } else {
                    assert_eq!(event["reconcile"], Value::Null);
                }
            }
        }
    }
    #[test]
    fn missing_proof_in_a_possible_view_is_model_incomplete_not_pruned_by_allowed() {
        let mut v = independent_commands(2, true);
        let proof = json!({"challenge_id":"00000000-0000-0000-0000-000000000123","nonce":"synthetic-proof"});
        v["initial"]["proofs"] = json!([proof["challenge_id"]]);
        for c in v["commands"].as_array_mut().unwrap() {
            c["guard"]["proof"] = proof.clone();
            refresh_completion(c);
        }
        v["commands"][0]["schedule"]["world_commit"] = false.into();
        v["commands"][1]["schedule"]["cut"] = "none".into();
        let out = run(&v);
        let event = &out["projection"][1];
        assert_eq!(out["knowledge_stop"]["reason"], "KnowledgeModelIncomplete");
        assert_eq!(event["coordinator"]["outcome"], "Completed");
        assert_eq!(event["witness"]["kind"], "ReceiptKnown");
        assert_eq!(event["caller"]["reservation_receipt"], true);
        assert_eq!(event["caller"]["knowledge_complete"], false);
        assert_eq!(event["caller"]["possible_states"], Value::Null);
        assert_eq!(event["caller"]["active_min"], Value::Null);
        assert_eq!(event["caller"]["active_max"], Value::Null);
        assert_eq!(out["execution"], "Inconclusive");
    }
    #[test]
    fn equal_occupancy_does_not_merge_different_proofs_sequences_or_fences() {
        let mut v = independent_commands(2, true);
        v["initial"]["proofs"] = json!(["00000000-0000-0000-0000-000000000123"]);
        let first = &mut v["commands"][0];
        first["action"] = "guard_persistent".into();
        first["guard"]["proof"] = json!({"challenge_id":"00000000-0000-0000-0000-000000000123","nonce":"synthetic-proof"});
        refresh_completion(first);
        let second = &mut v["commands"][1];
        second["action"] = "guard_memory".into();
        second["schedule"]["cut"] = "none".into();
        refresh_completion(second);
        let out = run(&v);
        assert_eq!(out["projection"][1]["caller"]["active_min"], 0);
        assert_eq!(out["projection"][1]["caller"]["active_max"], 0);
        assert_eq!(out["projection"][1]["caller"]["possible_states"], 2);

        let mut v = independent_commands(2, true);
        v["bindings"]["leases"]
            .as_array_mut()
            .unwrap()
            .push(json!({"label":"old-lease",
            "uuid":"30000000-0000-0000-0000-000000000002"}));
        v["initial"]["rows"] = json!([{"actor":"actor-a","key":"key-1","payload_tag":"payload-a",
            "state":"pending","expires_at_us":1_800_000_000,"lease":"old-lease","lease_until_us":0}]);
        v["commands"][0]["guard"]["actor_sequence_delta"] = 0.into();
        refresh_completion(&mut v["commands"][0]);
        let second = &mut v["commands"][1];
        second["action"] = "guard_memory".into();
        second["schedule"]["cut"] = "none".into();
        refresh_completion(second);
        let out = run(&v);
        assert_eq!(out["projection"][1]["caller"]["active_min"], 1);
        assert_eq!(out["projection"][1]["caller"]["active_max"], 1);
        assert_eq!(out["projection"][1]["caller"]["possible_states"], 2);
    }
    #[test]
    fn attempted_fanout_stops_without_dropping_alternatives_or_actual_outcome() {
        let v = independent_commands(8, true);
        let out = run(&v);
        assert_eq!(out["projection"].as_array().unwrap().len(), 7);
        assert_eq!(out["projection"][5]["caller"]["possible_states"], 64);
        assert_eq!(out["projection"][6]["coordinator"]["outcome"], "Unknown");
        assert_eq!(out["projection"][6]["caller"]["knowledge_complete"], false);
        assert_eq!(out["projection"][6]["caller"]["retained_max"], Value::Null);
        assert_eq!(
            out["knowledge_stop"],
            json!({"index":6,
            "phase":"AfterCommand","reason":"ViewBudget"})
        );
        assert_eq!(out["execution"], "Inconclusive");
        assert_eq!(out["terminal"], false);
        assert_eq!(out["evidence_complete"], false);
    }
    #[test]
    fn actual_capacity_failure_is_retained_even_when_its_detail_exceeds_event_budget() {
        let mut v = input();
        let c = &mut v["commands"][0];
        c["action"] = "finalize".into();
        refresh_completion(c);
        let mut rows = vec![
            json!({"actor":"actor-a","key":"key-a","payload_tag":"payload-a",
            "state":"pending","expires_at_us":0,"lease":"lease-a","lease_until_us":60_000_000}),
        ];
        for index in 0..4096 {
            let key = format!("occupied-{index}");
            v["bindings"]["keys"]
                .as_array_mut()
                .unwrap()
                .push(json!({"label":key,
                "key_id":"synthetic-key","hex":format!("{:064x}",index+1000)}));
            rows.push(
                json!({"actor":"actor-a","key":key,"payload_tag":"payload-a","state":"accepted",
                "expires_at_us":21_600_000_000i64,"lease":"lease-a","lease_until_us":0}),
            );
        }
        v["initial"]["rows"] = rows.into();
        v["budgets"]["events"] = 1.into();
        let out = run(&v);
        assert_eq!(out["projection"], json!([]));
        assert_eq!(out["safety_failure"], json!({"index":0,"active":4097}));
        assert_eq!(out["execution"], "Inconclusive");
        assert_eq!(out["evidence_complete"], false);
    }
}
