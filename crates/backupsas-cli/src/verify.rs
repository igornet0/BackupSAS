use anyhow::{Context, Result};
use backupsas_core::{BackupId, VerifyResult, verify_backup_dir};
use backupsas_server::load_config;
use backupsas_storage::{BackupRecord, StorageRoot, paths};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub data_dir: PathBuf,
    pub backup_id: Option<String>,
    pub all: bool,
    pub repository: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifyReportLine {
    pub backup_id: BackupId,
    pub repository: String,
    pub path: PathBuf,
    pub result: VerifyResult,
}

pub fn run_verify(opts: VerifyOptions) -> Result<Vec<VerifyReportLine>> {
    if opts.backup_id.is_some() && opts.all {
        anyhow::bail!("use either --backup-id or --all, not both");
    }
    if opts.backup_id.is_none() && !opts.all {
        anyhow::bail!("specify --backup-id <id> or --all");
    }

    let config = load_config(&opts.data_dir)
        .with_context(|| format!("failed to load {}/server.toml", opts.data_dir.display()))?;
    let storage = StorageRoot::open(&config)?;
    let mut lines = Vec::new();

    if let Some(id) = opts.backup_id {
        let id: BackupId = id.parse()?;
        let (repo, record) = storage.find_backup(&id)?;
        if let Some(repo_filter) = &opts.repository
            && repo.name() != repo_filter
        {
            anyhow::bail!(
                "backup {id} is in repository `{}`, not `{repo_filter}`",
                repo.name()
            );
        }
        let path = backup_verify_path(repo, &record);
        let result = verify_backup_dir(&path);
        lines.push(VerifyReportLine {
            backup_id: id,
            repository: repo.name().to_string(),
            path,
            result,
        });
    } else {
        for (repo_name, record) in storage.list_all()? {
            if let Some(repo_filter) = &opts.repository
                && &repo_name != repo_filter
            {
                continue;
            }
            let backup_id = match &record {
                BackupRecord::Uploading(s) => s.backup_id,
                BackupRecord::Complete { metadata, .. } => metadata.backup_id,
            };
            let repo = storage.repo(&repo_name)?;
            let path = backup_verify_path(repo, &record);
            let result = verify_backup_dir(&path);
            lines.push(VerifyReportLine {
                backup_id,
                repository: repo_name,
                path,
                result,
            });
        }
    }

    Ok(lines)
}

pub fn format_report(line: &VerifyReportLine) -> String {
    let mut out = String::new();
    out.push_str(&format!("backup {}\n", line.backup_id));
    out.push_str(&format!("repository {}\n", line.repository));
    out.push_str(&format!("path {}\n", line.path.display()));
    if line.result.valid {
        out.push_str("VALID\n");
        return out;
    }
    out.push_str("INVALID\n");
    for (i, failure) in line.result.failures.iter().enumerate() {
        let prefix = if i == 0 { "└── " } else { "    " };
        out.push_str(&format!("{prefix}{failure}\n"));
    }
    out
}

pub fn format_all(lines: &[VerifyReportLine]) -> String {
    lines.iter().map(format_report).collect()
}

pub fn any_invalid(lines: &[VerifyReportLine]) -> bool {
    lines.iter().any(|line| !line.result.valid)
}

fn backup_verify_path(repo: &backupsas_storage::FsRepository, record: &BackupRecord) -> PathBuf {
    match record {
        BackupRecord::Complete { path, .. } => path.clone(),
        BackupRecord::Uploading(session) => paths::staging_dir(repo.root(), &session.backup_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backupsas_core::verify_backup_dir;

    #[test]
    fn format_valid_report() {
        let line = VerifyReportLine {
            backup_id: BackupId::new(),
            repository: "test".into(),
            path: PathBuf::from("/tmp/backup"),
            result: verify_backup_dir(std::path::Path::new("/nonexistent")),
        };
        let text = format_report(&line);
        assert!(text.contains("backup "));
        assert!(text.contains("repository test"));
    }
}
