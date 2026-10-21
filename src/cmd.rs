//! Running external commands with a timeout.

use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Runs `cmd` with stdin closed and its output captured. The child is killed if
/// it has not exited within `timeout`.
pub fn run(cmd: &mut Command, timeout: Duration) -> io::Result<Output> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Drain both pipes concurrently so a chatty child cannot block on a full pipe.
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out after {}s", timeout.as_secs()),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };

    // A daemonized grandchild may keep the pipes open: don't wait for it forever.
    let collect = |rx: mpsc::Receiver<String>| {
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_default()
    };
    Ok(Output {
        status,
        stdout: collect(stdout),
        stderr: collect(stderr),
    })
}

/// Describes a failure to run `program` for display in a check's detail.
pub fn describe_error(program: &Path, err: &io::Error) -> String {
    let in_path = program.components().count() == 1;
    let program = program.display();
    match err.kind() {
        io::ErrorKind::NotFound if in_path => format!("`{program}` not found in PATH"),
        io::ErrorKind::NotFound => format!("`{program}` not found"),
        io::ErrorKind::TimedOut => format!("`{program}` {err}"),
        _ => format!("failed to run `{program}`: {err}"),
    }
}

/// Returns the first non-empty line of a command's error output.
pub fn first_line(stderr: &str) -> Option<&str> {
    stderr.lines().map(str::trim).find(|line| !line.is_empty())
}

fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_output_and_status() {
        let out = run(
            Command::new("sh").args(["-c", "echo out; echo err >&2; exit 3"]),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(out.stdout, "out\n");
        assert_eq!(out.stderr, "err\n");
        assert_eq!(out.status.code(), Some(3));
    }

    #[test]
    fn kills_on_timeout() {
        let started = Instant::now();
        let err = run(Command::new("sleep").arg("5"), Duration::from_millis(100)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn missing_program() {
        let err = run(
            &mut Command::new("lock-indicator-does-not-exist"),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(
            describe_error(Path::new("x"), &err),
            "`x` not found in PATH"
        );
        assert_eq!(
            describe_error(Path::new("/opt/x"), &err),
            "`/opt/x` not found"
        );
    }
}
