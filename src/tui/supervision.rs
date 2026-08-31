//! Launch-scoped ownership for full-screen TUI asynchronous work.

use std::future::Future;
use std::sync::{Mutex, MutexGuard};

use crate::runtime::{CallId, CancellationHandle, CancellationId, CancellationReason};

/// User-visible class of work owned by one TUI call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum TuiTaskKind {
    ModelTurn,
    PluginAgent,
    Hook,
    Mcp,
    ProviderDiscovery,
    ModelDiscovery,
    Filesystem,
    Process,
}

impl TuiTaskKind {
    pub(super) const fn supersedes_previous(self) -> bool {
        matches!(self, Self::ProviderDiscovery | Self::ModelDiscovery)
    }
}

/// Observed terminal state of one owned asynchronous call.
#[derive(Debug)]
pub(super) enum TuiTaskOutcome {
    Completed,
    Cancelled(crate::runtime::CancellationReceipt),
    Panicked(String),
}

/// Joined completion for one call-correlated task.
#[derive(Debug)]
pub(super) struct TuiTaskCompletion {
    pub(super) call_id: CallId,
    pub(super) kind: TuiTaskKind,
    pub(super) outcome: TuiTaskOutcome,
}

struct OwnedTask {
    call_id: CallId,
    kind: TuiTaskKind,
    cancellation: CancellationHandle,
    handle: tokio::task::JoinHandle<TuiTaskOutcome>,
}

type ActiveShutdown = Option<(CancellationId, CancellationHandle)>;

static ACTIVE_TUI_SHUTDOWN: Mutex<ActiveShutdown> = Mutex::new(None);

fn active_shutdown() -> MutexGuard<'static, ActiveShutdown> {
    ACTIVE_TUI_SHUTDOWN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Cancel the currently registered TUI launch, if one exists.
///
/// A request made while no TUI is active is deliberately not retained. The
/// next in-process launch receives its own fresh cancellation generation.
pub(super) fn request_active_tui_shutdown() {
    let cancellation = active_shutdown()
        .as_ref()
        .map(|(_, cancellation)| cancellation.clone());
    if let Some(cancellation) = cancellation {
        let _ = cancellation.cancel(CancellationReason::FrontendDisconnected);
    }
}

struct ShutdownRegistration {
    id: CancellationId,
}

impl ShutdownRegistration {
    fn install(cancellation: &CancellationHandle) -> Self {
        let id = cancellation.id();
        *active_shutdown() = Some((id, cancellation.clone()));
        Self { id }
    }
}

impl Drop for ShutdownRegistration {
    fn drop(&mut self) {
        let mut active = active_shutdown();
        if active.as_ref().is_some_and(|(id, _)| *id == self.id) {
            *active = None;
        }
    }
}

/// Fresh cancellation generation and task owner for one `App::run` call.
pub(super) struct TuiSupervisor {
    runtime: tokio::runtime::Handle,
    cancellation: CancellationHandle,
    tasks: Vec<OwnedTask>,
    _shutdown_registration: ShutdownRegistration,
}

impl TuiSupervisor {
    pub(super) fn new(runtime: tokio::runtime::Handle) -> Self {
        let cancellation = crate::runtime::CancellationTree::new().root();
        let shutdown_registration = ShutdownRegistration::install(&cancellation);
        Self {
            runtime,
            cancellation,
            tasks: Vec::new(),
            _shutdown_registration: shutdown_registration,
        }
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub(super) fn contains(&self, call_id: CallId) -> bool {
        self.tasks.iter().any(|task| task.call_id == call_id)
    }

    pub(super) fn spawn<F>(&mut self, call_id: CallId, kind: TuiTaskKind, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let cancellation = self.cancellation.child();
        let task_cancellation = cancellation.clone();
        let handle = self.runtime.spawn(async move {
            tokio::select! {
                receipt = task_cancellation.cancelled() => TuiTaskOutcome::Cancelled(receipt),
                () = future => TuiTaskOutcome::Completed,
            }
        });
        self.tasks.push(OwnedTask {
            call_id,
            kind,
            cancellation,
            handle,
        });
    }

    pub(super) fn cancel_call(&self, call_id: CallId, reason: &CancellationReason) {
        for task in self.tasks.iter().filter(|task| task.call_id == call_id) {
            let _ = task.cancellation.cancel((*reason).clone());
        }
    }

    pub(super) async fn reap_finished(&mut self) -> Vec<TuiTaskCompletion> {
        let mut finished = Vec::new();
        let mut index = 0;
        while index < self.tasks.len() {
            if !self.tasks[index].handle.is_finished() {
                index += 1;
                continue;
            }
            let task = self.tasks.swap_remove(index);
            finished.push(join_task(task).await);
        }
        finished
    }

    pub(super) async fn cancel_and_join(
        &mut self,
        reason: CancellationReason,
    ) -> Vec<TuiTaskCompletion> {
        let _ = self.cancellation.cancel(reason);
        let tasks = std::mem::take(&mut self.tasks);
        let mut finished = Vec::with_capacity(tasks.len());
        for task in tasks {
            finished.push(join_task(task).await);
        }
        finished
    }
}

impl Drop for TuiSupervisor {
    fn drop(&mut self) {
        let _ = self
            .cancellation
            .cancel(CancellationReason::ParentTerminated);
        for task in &self.tasks {
            task.handle.abort();
        }
    }
}

async fn join_task(task: OwnedTask) -> TuiTaskCompletion {
    let outcome = match task.handle.await {
        Ok(outcome) => outcome,
        Err(error) if error.is_cancelled() => {
            let receipt = task.cancellation.receipt().unwrap_or_else(|| {
                task.cancellation
                    .cancel(CancellationReason::ParentTerminated)
            });
            TuiTaskOutcome::Cancelled(receipt)
        }
        Err(error) => TuiTaskOutcome::Panicked(error.to_string()),
    };
    TuiTaskCompletion {
        call_id: task.call_id,
        kind: task.kind,
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelling_a_call_joins_and_drops_its_future() {
        struct DropNotice(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropNotice {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Release);
            }
        }

        let mut supervisor = TuiSupervisor::new(tokio::runtime::Handle::current());
        let call_id = CallId::new();
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_dropped = std::sync::Arc::clone(&dropped);
        supervisor.spawn(call_id, TuiTaskKind::ModelTurn, async move {
            let _notice = DropNotice(task_dropped);
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;

        supervisor.cancel_call(call_id, &CancellationReason::User);
        tokio::task::yield_now().await;
        let completions = supervisor.reap_finished().await;

        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].call_id, call_id);
        assert!(matches!(
            completions[0].outcome,
            TuiTaskOutcome::Cancelled(crate::runtime::CancellationReceipt {
                reason: CancellationReason::User,
                ..
            })
        ));
        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn shutdown_is_launch_scoped_and_not_sticky() {
        request_active_tui_shutdown();
        let first = TuiSupervisor::new(tokio::runtime::Handle::current());
        assert!(!first.is_cancelled());

        request_active_tui_shutdown();
        assert!(first.is_cancelled());
        drop(first);

        let second = TuiSupervisor::new(tokio::runtime::Handle::current());
        assert!(!second.is_cancelled());
    }

    #[tokio::test]
    async fn launch_shutdown_joins_every_owned_task() {
        let mut supervisor = TuiSupervisor::new(tokio::runtime::Handle::current());
        let kinds = [
            TuiTaskKind::ModelTurn,
            TuiTaskKind::PluginAgent,
            TuiTaskKind::Hook,
            TuiTaskKind::Mcp,
            TuiTaskKind::ProviderDiscovery,
            TuiTaskKind::ModelDiscovery,
            TuiTaskKind::Filesystem,
            TuiTaskKind::Process,
        ];
        let expected = kinds.len();
        for kind in kinds {
            supervisor.spawn(CallId::new(), kind, std::future::pending());
        }
        tokio::task::yield_now().await;

        let completions = supervisor
            .cancel_and_join(CancellationReason::FrontendDisconnected)
            .await;

        assert_eq!(completions.len(), expected);
        assert!(completions.iter().all(|completion| matches!(
            completion.outcome,
            TuiTaskOutcome::Cancelled(crate::runtime::CancellationReceipt {
                reason: CancellationReason::FrontendDisconnected,
                ..
            })
        )));
    }
}
