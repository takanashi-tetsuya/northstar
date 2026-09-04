//! Structured worker supervision with criticality-aware shutdown.

use std::future::Future;
use tokio::task::JoinSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCriticality {
    Critical,
    NonCritical,
}

pub struct WorkerGroup {
    tasks: JoinSet<(String, WorkerCriticality)>,
}

impl WorkerGroup {
    pub fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
        }
    }

    pub fn spawn<F>(&mut self, name: impl Into<String>, criticality: WorkerCriticality, task: F)
    where
        F: Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send + 'static,
    {
        let name = name.into();
        self.tasks.spawn(async move {
            let result = task.await;
            if let Err(error) = result {
                tracing::error!(worker = %name, error = %error, "worker exited with error");
            }
            (name, criticality)
        });
    }

    pub async fn join_next(&mut self) -> Option<(String, WorkerCriticality)> {
        self.tasks.join_next().await.and_then(Result::ok)
    }

    pub async fn shutdown(&mut self) {
        self.tasks.shutdown().await;
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

impl Default for WorkerGroup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn worker_completion_is_observable() {
        let mut group = WorkerGroup::new();
        group.spawn("test", WorkerCriticality::Critical, async { Ok(()) });
        let (name, criticality) = group.join_next().await.unwrap();
        assert_eq!(name, "test");
        assert_eq!(criticality, WorkerCriticality::Critical);
    }
}
