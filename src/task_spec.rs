//! Task specification derived from user-authored ledger observations.

use crate::evidence::Denial;
use crate::ledger::{EvidenceTrust, ObsId, ObservationKind, RealityLedger};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSpec {
    pub content: String,
    pub source_obs: ObsId,
    pub created_at: DateTime<Utc>,
}

impl TaskSpec {
    /// Build a task specification from a user-authored observation.
    ///
    /// # Errors
    ///
    /// Returns [`Denial`] when the observation is missing, is not from user
    /// provenance, or is not a user-task observation.
    pub fn from_user_observation(
        ledger: &RealityLedger,
        run: &crate::tools::ToolRunContext,
        source_obs: ObsId,
    ) -> Result<Self, Denial> {
        let observation = ledger
            .get(source_obs)
            .ok_or_else(|| Denial::new(format!("unknown task observation {source_obs}")))?;
        if observation.provenance.trust != EvidenceTrust::UserInput
            || !observation.provenance.is_bound_to(run)
        {
            return Err(Denial::new(
                "task spec must come from current-run user input",
            ));
        }
        let ObservationKind::UserTask { content } = &observation.kind else {
            return Err(Denial::new("task spec source must be a user task"));
        };
        Ok(Self {
            content: content.clone(),
            source_obs,
            created_at: observation.ts,
        })
    }
}
