//! Strongly typed identifiers and generations for the runtime kernel.

use std::fmt;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! uuid_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Create a fresh identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Construct an identifier from an already validated UUID.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Return the UUID value.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(RunId, "Identity of one canonical agent run.");
uuid_id!(
    WorkspaceHandleId,
    "Opaque identity of one isolated workspace lifecycle."
);
uuid_id!(
    CallId,
    "Identity of one provider, tool, hook, or persistence call."
);
uuid_id!(ActorId, "Identity of an actor participating in a run.");
uuid_id!(
    CancellationId,
    "Identity of a node in a run's cancellation tree."
);
uuid_id!(BudgetId, "Identity of a run budget allocation.");

macro_rules! generation {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Construct a non-zero generation.
            #[must_use]
            pub const fn new(value: u64) -> Option<Self> {
                match NonZeroU64::new(value) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }

            /// Return the underlying generation number.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

generation!(
    WorkspaceGeneration,
    "Monotonic generation of the workspace snapshot bound to a run."
);
generation!(
    CapabilityGeneration,
    "Monotonic generation of the capability manifest bound to a run."
);
generation!(
    BudgetGeneration,
    "Monotonic generation of the budget policy bound to a run."
);
generation!(
    StateGeneration,
    "Monotonic generation of committed canonical run state."
);
generation!(
    ContinuationGeneration,
    "Monotonic generation of provider-owned continuation state."
);
