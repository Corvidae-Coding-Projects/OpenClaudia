//! Regenerate the user-facing capability matrix from the validated registry.

use std::error::Error;
use std::io::Write as _;
use std::path::Path;

use openclaudia::capability_evidence::CapabilityEvidenceBundle;

fn main() -> Result<(), Box<dyn Error>> {
    let matrix = CapabilityEvidenceBundle::bundled()?.render_user_facing_markdown();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/binary-capability-matrix.md");
    let parent = path
        .parent()
        .ok_or("capability matrix path has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(matrix.as_bytes())?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(&path)?;
    println!("generated {}", path.display());
    Ok(())
}
