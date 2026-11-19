use crate::PostCommitPlan;

#[tokio::test]
async fn post_commit_plan_preserves_order_and_observes_failure_without_stopping() {
    let mut plan = PostCommitPlan::<u8, 3>::new();
    for step in [1, 2, 3] {
        plan.try_push(step).unwrap();
    }
    let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let failures = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    plan.run(
        {
            let observed = observed.clone();
            move |step| {
                let observed = observed.clone();
                async move {
                    observed.lock().unwrap().push(step);
                    if step == 2 {
                        Err(step)
                    } else {
                        Ok(())
                    }
                }
            }
        },
        {
            let failures = failures.clone();
            move |step| failures.lock().unwrap().push(step)
        },
    )
    .await;
    assert_eq!(*observed.lock().unwrap(), vec![1, 2, 3]);
    assert_eq!(*failures.lock().unwrap(), vec![2]);
}
