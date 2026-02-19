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
/// Applies a strict seccomp BPF allowlist for the guard-worker process.
/// Denies ptrace, process_vm_readv, kexec_load with EPERM.
/// Anything outside the allowlist returns EPERM rather than kill, so missed
/// syscalls surface as errors instead of silent process termination.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub fn apply_guard_worker_seccomp() -> Result<(), SandboxError> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    // Syscalls needed by tokio + reqwest (HTTP to local LLM) + stdin/stdout JSON protocol.
    // Kept minimal; nothing that enables ptrace, raw memory access, or kernel loading.
    #[rustfmt::skip]
    let allowed: &[i64] = &[
        libc::SYS_read, libc::SYS_write, libc::SYS_readv, libc::SYS_writev,
        libc::SYS_openat, libc::SYS_close, libc::SYS_fstat, libc::SYS_stat,
        libc::SYS_lstat, libc::SYS_lseek, libc::SYS_mmap, libc::SYS_mprotect,
        libc::SYS_munmap, libc::SYS_brk, libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn, libc::SYS_ioctl,
        libc::SYS_pread64, libc::SYS_pwrite64, libc::SYS_getcwd,
        libc::SYS_clone, libc::SYS_exit, libc::SYS_exit_group,
        libc::SYS_futex, libc::SYS_sched_yield, libc::SYS_nanosleep,
        libc::SYS_clock_gettime, libc::SYS_gettimeofday,
        libc::SYS_socket, libc::SYS_connect, libc::SYS_accept4,
        libc::SYS_sendto, libc::SYS_recvfrom, libc::SYS_sendmsg,
        libc::SYS_recvmsg, libc::SYS_shutdown, libc::SYS_bind,
        libc::SYS_getsockname, libc::SYS_getpeername,
        libc::SYS_setsockopt, libc::SYS_getsockopt,
        libc::SYS_epoll_create1, libc::SYS_epoll_ctl, libc::SYS_epoll_pwait,
        libc::SYS_poll, libc::SYS_ppoll,
        libc::SYS_prctl, libc::SYS_prlimit64,
        libc::SYS_getuid, libc::SYS_getgid, libc::SYS_getpid, libc::SYS_gettid,
        libc::SYS_set_robust_list, libc::SYS_getrandom, libc::SYS_madvise,
        libc::SYS_pipe2, libc::SYS_eventfd2, libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime, libc::SYS_wait4, libc::SYS_fcntl,
        libc::SYS_dup, libc::SYS_dup3, libc::SYS_set_tid_address,
        libc::SYS_sigaltstack, libc::SYS_uname,
        // needed by newer glibc / musl thread initialisation
        libc::SYS_rseq, libc::SYS_memfd_create,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_arch_prctl,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_newfstatat,
    ];

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in allowed {
        rules.insert(nr, vec![]);
    }

    #[cfg(target_arch = "x86_64")]
    let arch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = seccompiler::TargetArch::aarch64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("seccomp filter not implemented for this architecture");

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| SandboxError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    let bpf: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::Error| SandboxError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    seccompiler::apply_filter(&bpf)
        .map_err(|e| SandboxError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    Ok(())
}

/// Seccomp stub for the guard worker on non-Linux or when the sandbox feature is disabled.
#[cfg(not(all(target_os = "linux", feature = "sandbox")))]
pub fn apply_guard_worker_seccomp() -> Result<(), SandboxError> {
    Ok(())
}

/// Applies seccomp to the main process (Linux + sandbox feature only).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub fn apply_main_process_seccomp() -> Result<(), SandboxError> {
    // The guard worker has a strict filter; the main process uses Landlock + rlimits
    // (applied via apply_child_sandbox in pre_exec). A full main-process seccomp filter
    // would need the entire axum/sqlx/reqwest syscall surface and is left for a
    // dedicated audit. Dangerous calls are blocked at the child level.
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

        // Limit open file descriptors to prevent file descriptor exhaustion attacks.
        let fd_limit = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        libc::setrlimit(libc::RLIMIT_NOFILE, &fd_limit);
    }
}
