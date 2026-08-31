//! BackupSAS CLI library (verify command for tests and tooling).

pub mod verify;

pub use verify::{run_verify, VerifyOptions, VerifyReportLine};
