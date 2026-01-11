use clap::Parser;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::collections::HashSet;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_WAIT_PER_SIGNAL: Duration = Duration::from_secs(2);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(name = "murder")]
#[command(about = "Kill processes bound to specified ports using progressively aggressive signals")]
struct Cli {
    #[arg(required = true)]
    ports: Vec<u16>,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: i32,
    name: Option<String>,
}

fn find_pids_for_port(port: u16) -> Vec<ProcessInfo> {
    #[cfg(target_os = "macos")]
    {
        find_pids_macos(port)
    }
    #[cfg(target_os = "linux")]
    {
        find_pids_linux(port)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        eprintln!("Unsupported platform");
        vec![]
    }
}

#[cfg(target_os = "macos")]
fn find_pids_macos(port: u16) -> Vec<ProcessInfo> {
    let output = Command::new("lsof")
        .args(["-i", &format!("TCP:{}", port), "-t"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout
                .lines()
                .filter_map(|line| line.trim().parse::<i32>().ok())
                .map(|pid| {
                    let name = get_process_name(pid);
                    ProcessInfo { pid, name }
                })
                .collect()
        }
        _ => vec![],
    }
}

#[cfg(target_os = "linux")]
fn find_pids_linux(port: u16) -> Vec<ProcessInfo> {
    let output = Command::new("ss")
        .args(["-tlnp", &format!("sport = :{}", port)])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut pids = Vec::new();
            for line in stdout.lines().skip(1) {
                if let Some(pid_info) = extract_pid_from_ss_line(line) {
                    pids.push(pid_info);
                }
            }
            pids
        }
        _ => {
            parse_proc_net_tcp(port)
        }
    }
}

#[cfg(target_os = "linux")]
fn extract_pid_from_ss_line(line: &str) -> Option<ProcessInfo> {
    if let Some(start) = line.find("pid=") {
        let rest = &line[start + 4..];
        let pid_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pid) = pid_str.parse::<i32>() {
            let name = get_process_name(pid);
            return Some(ProcessInfo { pid, name });
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp(port: u16) -> Vec<ProcessInfo> {
    use std::fs;
    use std::path::Path;

    let port_hex = format!("{:04X}", port);
    let mut pids = Vec::new();

    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 1 {
                let local_addr = parts[1];
                if let Some(addr_port) = local_addr.split(':').nth(1) {
                    if addr_port == port_hex {
                        if let Some(inode) = parts.get(9) {
                            if let Some(pid) = find_pid_by_inode(inode) {
                                let name = get_process_name(pid);
                                pids.push(ProcessInfo { pid, name });
                            }
                        }
                    }
                }
            }
        }
    }
    pids
}

#[cfg(target_os = "linux")]
fn find_pid_by_inode(inode: &str) -> Option<i32> {
    use std::fs;
    use std::path::Path;

    let proc_dir = Path::new("/proc");
    if let Ok(entries) = fs::read_dir(proc_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name() {
                if let Some(name_str) = name.to_str() {
                    if let Ok(pid) = name_str.parse::<i32>() {
                        let fd_dir = path.join("fd");
                        if let Ok(fds) = fs::read_dir(&fd_dir) {
                            for fd in fds.flatten() {
                                if let Ok(link) = fs::read_link(fd.path()) {
                                    let link_str = link.to_string_lossy();
                                    if link_str.contains(&format!("socket:[{}]", inode)) {
                                        return Some(pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn get_process_name(pid: i32) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .ok()?;
        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
        None
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim().to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

fn process_exists(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}

fn send_signal(pid: i32, signal: Signal) -> Result<(), nix::errno::Errno> {
    kill(Pid::from_raw(pid), signal)
}

async fn kill_process(port: u16, process: ProcessInfo) -> Result<(), String> {
    let pid = process.pid;
    let name = process.name.as_deref().unwrap_or("unknown");

    println!("[{}] Found PID {} ({})", port, pid, name);

    let signals = [Signal::SIGINT, Signal::SIGTERM, Signal::SIGKILL];
    let signal_names = ["SIGINT", "SIGTERM", "SIGKILL"];

    let start = std::time::Instant::now();

    for (signal, signal_name) in signals.iter().zip(signal_names.iter()) {
        if start.elapsed() >= TOTAL_TIMEOUT {
            return Err(format!("Total timeout exceeded for PID {}", pid));
        }

        if !process_exists(pid) {
            println!("[{}] Process {} already terminated", port, pid);
            return Ok(());
        }

        println!("[{}] Sending {} to PID {}", port, signal_name, pid);

        match send_signal(pid, *signal) {
            Ok(()) => {}
            Err(nix::errno::Errno::EPERM) => {
                return Err(format!("EPERM: Permission denied for PID {}", pid));
            }
            Err(nix::errno::Errno::ESRCH) => {
                println!("[{}] Process terminated", port);
                return Ok(());
            }
            Err(e) => {
                return Err(format!("Failed to send signal to PID {}: {}", pid, e));
            }
        }

        let wait_result = timeout(MAX_WAIT_PER_SIGNAL, async {
            loop {
                sleep(POLL_INTERVAL).await;
                if !process_exists(pid) {
                    return true;
                }
                println!("[{}] Process still running, waiting...", port);
            }
        })
        .await;

        match wait_result {
            Ok(true) => {
                println!("[{}] Process terminated", port);
                return Ok(());
            }
            Ok(false) => {}
            Err(_) => {
                // Timeout, escalate to next signal
            }
        }
    }

    if process_exists(pid) {
        Err(format!("Failed to kill PID {} after all signals", pid))
    } else {
        println!("[{}] Process terminated", port);
        Ok(())
    }
}

async fn process_port(port: u16, processed_pids: Arc<Mutex<HashSet<i32>>>) -> Result<(), String> {
    let processes = find_pids_for_port(port);

    if processes.is_empty() {
        println!("[{}] No process bound to port", port);
        return Ok(());
    }

    let mut errors = Vec::new();

    for process in processes {
        {
            let mut pids = processed_pids.lock().await;
            if pids.contains(&process.pid) {
                println!(
                    "[{}] PID {} already being processed, skipping",
                    port, process.pid
                );
                continue;
            }
            pids.insert(process.pid);
        }

        if let Err(e) = kill_process(port, process).await {
            errors.push(e);
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn needs_sudo(errors: &[String]) -> bool {
    errors.iter().any(|e| e.contains("EPERM"))
}

fn re_exec_with_sudo() -> ! {
    let args: Vec<String> = std::env::args().collect();
    let exe = &args[0];
    let rest = &args[1..];

    eprintln!("Permission denied, re-executing with sudo...");

    let status = Command::new("sudo")
        .arg(exe)
        .args(rest)
        .status()
        .expect("Failed to execute sudo");

    std::process::exit(status.code().unwrap_or(1));
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let processed_pids = Arc::new(Mutex::new(HashSet::new()));

    let timeout_result = timeout(TOTAL_TIMEOUT, async {
        let handles: Vec<_> = cli
            .ports
            .iter()
            .map(|&port| {
                let pids = Arc::clone(&processed_pids);
                tokio::spawn(async move { process_port(port, pids).await })
            })
            .collect();

        let mut errors = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => errors.push(e),
                Err(e) => errors.push(format!("Task failed: {}", e)),
            }
        }
        errors
    })
    .await;

    let errors = match timeout_result {
        Ok(errors) => errors,
        Err(_) => {
            eprintln!("Total timeout of {} seconds exceeded", TOTAL_TIMEOUT.as_secs());
            std::process::exit(1);
        }
    };

    if needs_sudo(&errors) {
        re_exec_with_sudo();
    }

    if !errors.is_empty() {
        for error in &errors {
            eprintln!("Error: {}", error);
        }
        std::process::exit(1);
    }
}
