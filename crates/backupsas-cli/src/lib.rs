//! BackupSAS CLI library (verify command for tests and tooling).

pub mod verify;

pub use verify::{VerifyOptions, VerifyReportLine, run_verify};
