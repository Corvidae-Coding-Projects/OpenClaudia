//! Regenerate the artifact-bound S-105 retrieval evaluation.

use std::error::Error;
use std::io::Write as _;
use std::path::Path;

use openclaudia::memory::{build_technical_retrieval_evaluation, TechnicalRetrievalPolicyId};

const TUNING_CORPUS: &str = include_str!("../capabilities/technical-memory-retrieval-tuning.json");
const HELD_OUT_CORPUS: &str =
    include_str!("../capabilities/technical-memory-retrieval-heldout.json");

fn main() -> Result<(), Box<dyn Error>> {
    let evaluation = build_technical_retrieval_evaluation(
        TUNING_CORPUS,
        HELD_OUT_CORPUS,
        Path::new(env!("CARGO_MANIFEST_DIR")),
        3,
        TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
        "s105-evaluation-runner",
        "openclaudia-deterministic-retrieval-evaluator-v1",
    )?;
    let mut encoded = serde_json::to_string_pretty(&evaluation)?;
    encoded.push('\n');
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("capabilities/technical-memory-retrieval-evaluation.json");
    let parent = path.parent().ok_or("evaluation path has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(encoded.as_bytes())?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(&path)?;
    println!("generated {}", path.display());
    Ok(())
}
