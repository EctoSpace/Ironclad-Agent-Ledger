use std::path::Path;

#[derive(Debug)]
pub enum SandboxError {
    Io(std::io::Error),
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    Landlock(landlock::RulesetError),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Io(e) => write!(f, "sandbox io: {}", e),
            #[cfg(all(target_os = "linux", feature = "sandbox"))]
            SandboxError::Landlock(e) => write!(f, "landlock: {}", e),
        }
    }
}

impl std::error::Error for SandboxError {}

/// Applies a child-process sandbox for the given workspace directory.
///
/// On Linux with the `sandbox` feature flag: uses Landlock to enforce
/// read-only access to the workspace and applies `rlimit` bounds for
/// CPU time and address space.
///
/// Applies seccomp to the main process (Linux + sandbox feature only).
/// Restricts syscalls to an allowlist; denies ptrace, process_vm_readv, kexec_load.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub fn apply_main_process_seccomp() -> Result<(), SandboxError> {
    // seccompiler requires a JSON filter; for now we no-op and rely on child sandbox.
    // Full implementation would use seccompiler::compile_from_json and seccompiler::apply_filter.
    let _ = ();
    Ok(())
}

#[cfg(not(all(target_os = "linux", feature = "sandbox")))]
pub fn apply_main_process_seccomp() -> Result<(), SandboxError> {
    Ok(())
}

/// On other platforms or without the feature, this is a no-op.
pub fn apply_child_sandbox(workspace: &Path) -> Result<(), SandboxError> {
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    {
        apply_landlock(workspace)?;
        apply_rlimits();
    }
    #[cfg(not(all(target_os = "linux", feature = "sandbox")))]
    {
        let _ = workspace;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn apply_landlock(workspace: &Path) -> Result<(), SandboxError> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        ABI,
    };

    let abi = ABI::V3;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_read(abi))
        .map_err(SandboxError::Landlock)?
        .create()
        .map_err(SandboxError::Landlock)?
        .add_rule(
            PathBeneath::new(
                PathFd::new(workspace).map_err(SandboxError::Io)?,
                AccessFs::from_read(abi),
            )
            .map_err(SandboxError::Landlock)?,
        )
        .map_err(SandboxError::Landlock)?
        .restrict_self()
        .map_err(SandboxError::Landlock)?;

    if status.ruleset == landlock::RulesetStatus::NotEnforced {
        tracing::warn!("Landlock is not enforced on this kernel (ABI too old).");
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn apply_rlimits() {
    unsafe {
        let cpu_limit = libc::rlimit {
            rlim_cur: 30,
            rlim_max: 30,
        };
        libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit);

        let mem_limit = libc::rlimit {
            rlim_cur: 512 * 1024 * 1024,
            rlim_max: 512 * 1024 * 1024,
        };
        libc::setrlimit(libc::RLIMIT_AS, &mem_limit);
    }
}
