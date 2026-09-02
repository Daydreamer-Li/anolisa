use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use asc_daemon::{BootstrapConfig, serve_without_handlers};
use asc_daemon_service::ShutdownToken;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

static DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

struct RunningBinary {
    child: Child,
    directory: PathBuf,
    socket_path: PathBuf,
}

impl Drop for RunningBinary {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn unique_directory() -> PathBuf {
    std::env::temp_dir().join(format!(
        "asc-daemon-bootstrap-{}-{}",
        std::process::id(),
        DIRECTORY_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

async fn wait_for_socket(path: &Path) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("daemon bootstrap should bind its socket");
}

async fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SIGTERM should stop the foreground daemon")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_serves_transport_without_methods_and_cleans_up() {
    let directory = unique_directory();
    std::fs::create_dir(&directory).unwrap();
    let socket_path = directory.join("daemon.sock");
    let shutdown = ShutdownToken::new();
    let service_shutdown = shutdown.clone();
    let config = BootstrapConfig::new(&socket_path);
    let service =
        tokio::spawn(async move { serve_without_handlers(config, service_shutdown).await });

    wait_for_socket(&socket_path).await;
    let mut stream = UnixStream::connect(&socket_path).await.unwrap();
    stream.write_all(b"unregistered request\n").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.is_empty());

    shutdown.request();
    let report = service.await.unwrap().unwrap();
    assert_eq!(report.accepted_connections, 1);
    assert_eq!(report.dispatched_requests, 1);
    assert_eq!(report.silently_closed_connections, 1);
    assert!(!socket_path.exists());
    std::fs::remove_dir(directory).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_starts_in_foreground_and_sigterm_cleans_its_socket() {
    let directory = unique_directory();
    std::fs::create_dir(&directory).unwrap();
    let socket_path = directory.join("daemon.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_asc-daemon"))
        .args(["serve", "--socket"])
        .arg(&socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut running = RunningBinary {
        child,
        directory,
        socket_path,
    };

    wait_for_socket(&running.socket_path).await;
    let signal = Command::new("/bin/kill")
        .arg("-TERM")
        .arg(running.child.id().to_string())
        .status()
        .unwrap();
    assert!(signal.success());
    let status = wait_for_exit(&mut running.child).await;

    assert!(status.success());
    assert!(!running.socket_path.exists());
}
