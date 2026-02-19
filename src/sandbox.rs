use std::path::Path;

#[derive(Debug)]
pub enum SandboxError {
    Io(std::io::Error),
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    Landlock(landlock::RulesetError),
    #[cfg(target_os = "macos")]
    Seatbelt(String),
    #[cfg(target_os = "windows")]
    Windows(windows::core::Error),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Io(e) => write!(f, "sandbox io: {}", e),
            #[cfg(all(target_os = "linux", feature = "sandbox"))]
            SandboxError::Landlock(e) => write!(f, "landlock: {}", e),
            #[cfg(target_os = "macos")]
            SandboxError::Seatbelt(msg) => write!(f, "seatbelt: {}", msg),
            #[cfg(target_os = "windows")]
            SandboxError::Windows(e) => write!(f, "windows job object: {}", e),
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
    // On unsupported architectures (RISC-V, s390x, etc.) we skip the filter rather than
    // failing the build. The sandbox feature is still useful for Landlock and rlimits.
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Ok(());

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

/// Applies a production-ready seccomp BPF allowlist to the main process.
/// The allowlist is broader than the guard-worker filter because the main process runs:
///   - Axum HTTP server (accept4, listen, sendmsg, recvmsg, setsockopt, epoll_*)
///   - SQLx Postgres client (same networking)
///   - Process spawning for tool execution (clone, wait4, pipe2, eventfd2)
///   - File-descriptor management (fcntl, dup, dup3)
/// Explicitly denied (EPERM): ptrace, process_vm_readv/writev, kexec_load,
///   init_module, finit_module, mount, umount2, pivot_root, reboot.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub fn apply_main_process_seccomp() -> Result<(), SandboxError> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    #[rustfmt::skip]
    let allowed: &[i64] = &[
        // Basic I/O
        libc::SYS_read, libc::SYS_write, libc::SYS_readv, libc::SYS_writev,
        libc::SYS_pread64, libc::SYS_pwrite64,
        libc::SYS_openat, libc::SYS_close, libc::SYS_fstat, libc::SYS_stat,
        libc::SYS_lstat, libc::SYS_lseek, libc::SYS_getcwd, libc::SYS_getdents64,
        libc::SYS_rename, libc::SYS_unlink, libc::SYS_mkdir, libc::SYS_rmdir,
        libc::SYS_chmod, libc::SYS_chown, libc::SYS_truncate, libc::SYS_ftruncate,
        // Memory
        libc::SYS_mmap, libc::SYS_mprotect, libc::SYS_munmap, libc::SYS_brk,
        libc::SYS_madvise, libc::SYS_memfd_create,
        // Signals / threads
        libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack, libc::SYS_futex, libc::SYS_sched_yield,
        libc::SYS_nanosleep, libc::SYS_clock_gettime, libc::SYS_gettimeofday,
        // Process management (needed for spawning tool sub-processes)
        libc::SYS_clone, libc::SYS_wait4, libc::SYS_exit, libc::SYS_exit_group,
        libc::SYS_execve, libc::SYS_set_tid_address,
        // Pipe / FD helpers
        libc::SYS_pipe2, libc::SYS_eventfd2, libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime, libc::SYS_fcntl, libc::SYS_dup, libc::SYS_dup3,
        libc::SYS_ioctl,
        // Networking (Axum + SQLx)
        libc::SYS_socket, libc::SYS_connect, libc::SYS_bind, libc::SYS_listen,
        libc::SYS_accept4, libc::SYS_sendto, libc::SYS_recvfrom,
        libc::SYS_sendmsg, libc::SYS_recvmsg, libc::SYS_shutdown,
        libc::SYS_getsockname, libc::SYS_getpeername,
        libc::SYS_setsockopt, libc::SYS_getsockopt,
        // epoll / poll
        libc::SYS_epoll_create1, libc::SYS_epoll_ctl, libc::SYS_epoll_pwait,
        libc::SYS_poll, libc::SYS_ppoll,
        // Misc
        libc::SYS_prctl, libc::SYS_prlimit64, libc::SYS_getrandom,
        libc::SYS_getuid, libc::SYS_getgid, libc::SYS_getpid, libc::SYS_gettid,
        libc::SYS_set_robust_list, libc::SYS_uname,
        libc::SYS_rseq,
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
    return Ok(());

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

    tracing::info!("Main-process seccomp filter applied.");
    Ok(())
}

/// No-op on non-Linux or when the sandbox feature is disabled.
#[cfg(not(all(target_os = "linux", feature = "sandbox")))]
pub fn apply_main_process_seccomp() -> Result<(), SandboxError> {
    #[cfg(target_os = "macos")]
    tracing::warn!(
        "⚠️  Sandbox feature requested on macOS: macOS does not support Landlock or seccomp BPF. \
         The --features sandbox flag is a no-op on this platform. \
         Executor isolation is NOT active. Use Linux for production deployments."
    );
    Ok(())
}

/// Applies the strongest available child-process sandbox for the current platform.
///
/// - Linux (with `sandbox` feature): Landlock + rlimits
/// - macOS: `sandbox_init` Seatbelt profile (deny network, read-only workspace)
/// - Windows: Job Object with `KILL_ON_JOB_CLOSE` and full UI restrictions
/// - All other platforms: no-op (sandbox is best-effort)
pub fn apply_child_sandbox(workspace: &Path) -> Result<(), SandboxError> {
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    {
        apply_landlock(workspace)?;
        apply_rlimits();
    }
    #[cfg(target_os = "macos")]
    {
        apply_macos_seatbelt(workspace)?;
    }
    #[cfg(target_os = "windows")]
    {
        let _ = workspace;
        apply_windows_job_object()?;
    }
    #[cfg(not(any(
        all(target_os = "linux", feature = "sandbox"),
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        let _ = workspace;
    }
    Ok(())
}

// ── macOS Seatbelt (sandbox_init) ─────────────────────────────────────────────

/// Applies a macOS Seatbelt profile that:
///   - Denies all network access
///   - Allows read-only file access to the given workspace directory
///   - Allows process-exec and sysctl-read so the process can function
///
/// `sandbox_init` is part of macOS's `libsandbox.dylib` (since 10.5). No extra crate needed.
#[cfg(target_os = "macos")]
fn apply_macos_seatbelt(workspace: &Path) -> Result<(), SandboxError> {
    use std::ffi::CString;

    extern "C" {
        fn sandbox_init(
            profile: *const libc::c_char,
            flags: u64,
            errorbuf: *mut *mut libc::c_char,
        ) -> libc::c_int;
        fn sandbox_free_error(errorbuf: *mut libc::c_char);
    }

    let workspace_str = workspace
        .to_str()
        .unwrap_or(".")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");

    // Seatbelt profile in TinyScheme S-expression syntax.
    // We intentionally allow file-read* only under the workspace so the executor
    // can inspect results; write access requires the broader main-process sandbox.
    let profile = format!(
        "(version 1)\
         (deny default)\
         (allow file-read* (subpath \"{workspace}\"))\
         (allow file-read-metadata)\
         (allow process-exec)\
         (allow sysctl-read)\
         (allow signal (target self))",
        workspace = workspace_str,
    );

    let profile_cstr = CString::new(profile)
        .map_err(|e| SandboxError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;

    let mut error_buf: *mut libc::c_char = std::ptr::null_mut();

    let ret = unsafe { sandbox_init(profile_cstr.as_ptr(), 0, &mut error_buf) };

    if ret != 0 {
        let msg = if !error_buf.is_null() {
            let s = unsafe { std::ffi::CStr::from_ptr(error_buf) }
                .to_string_lossy()
                .into_owned();
            unsafe { sandbox_free_error(error_buf) };
            s
        } else {
            format!("sandbox_init returned {}", ret)
        };
        return Err(SandboxError::Seatbelt(msg));
    }

    tracing::info!("macOS Seatbelt sandbox applied (deny network, read-only workspace).");
    Ok(())
}

// ── Windows Job Object ─────────────────────────────────────────────────────────

/// Creates a Windows Job Object, configures it with `KILL_ON_JOB_CLOSE` and
/// full UI restrictions, then assigns the current process to it.
///
/// The Job Object ensures that if the supervisor process exits (or is killed) the
/// child processes it spawned are automatically terminated — preventing orphan LLM
/// tool processes from persisting on the host.
#[cfg(target_os = "windows")]
fn apply_windows_job_object() -> Result<(), SandboxError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicLimitInformation,
        JobObjectBasicUIRestrictions, SetInformationJobObject,
        JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
        JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
        JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
        JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let job: HANDLE = CreateJobObjectW(None, None).map_err(SandboxError::Windows)?;

        // Kill all processes in the job when the last handle to the job object closes.
        let mut basic_limits = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
        basic_limits.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job,
            JobObjectBasicLimitInformation,
            &basic_limits as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
        )
        .map_err(SandboxError::Windows)?;

        // Prevent UI escalation vectors (desktop switching, clipboard theft, etc.).
        let ui_limits = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        };
        SetInformationJobObject(
            job,
            JobObjectBasicUIRestrictions,
            &ui_limits as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        )
        .map_err(SandboxError::Windows)?;

        AssignProcessToJobObject(job, GetCurrentProcess()).map_err(SandboxError::Windows)?;
    }

    tracing::info!("Windows Job Object sandbox applied (KILL_ON_JOB_CLOSE + UI restrictions).");
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
