#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let id = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock is after Unix epoch").as_nanos();
        let path = std::env::temp_dir().join(format!("monitor-traffic-cli-{}-{id}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).expect("create a private test directory");
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn diagnostics_are_offline_and_init_requires_an_explicit_seed() {
    let tmp = Temp::new();
    let config = tmp.0.join("traffic.json");
    let state = tmp.0.join("ledger/state.json");
    let seed = tmp.0.join("seed.json");
    fs::write(&config, json!({"state_file":state,"report":"billing"}).to_string()).unwrap();
    fs::write(
        &seed,
        json!({"boot_id":"synthetic/epoch","net_rx_total":1000,"net_tx_total":2000,"note":"test fixture"})
            .to_string(),
    )
    .unwrap();

    let run = |args: &[&str], success| {
        let output = Command::new(env!("CARGO_BIN_EXE_monitor-agent"))
            .env_clear()
            .env("MONITOR_TRAFFIC_CONFIG", &config)
            .env("MONITOR_IFACE", "lo")
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.success(), success, "{args:?}: {}", String::from_utf8_lossy(&output.stderr));
        if output.stdout.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&output.stdout).unwrap()
        }
    };

    let check = run(&["--traffic-check"], true);
    assert_eq!(check["iface"], "lo");
    assert_eq!(check["valid"], true);
    assert!(check["sample"]["links"]["lo"]["identity"]["ifindex"].as_u64().unwrap() > 0);
    let missing = run(&["--iface", "missing-test0", "--traffic-check"], false);
    assert_eq!(missing["valid"], false);
    assert_eq!(missing["sample"]["missing"], json!(["missing-test0"]));
    run(&["--traffic-status"], false);
    run(&["--traffic-check", "--traffic-status"], false);
    let directory = state.parent().unwrap();
    assert!(!directory.exists());

    run(&["--traffic-init", seed.to_str().unwrap()], true);
    let before = fs::read(&state).unwrap();
    let status = run(&["--traffic-status"], true);
    assert_eq!(status["report_totals"], json!({"rx":1000,"tx":2000}));
    assert_eq!(status["state"]["seed"]["boot_id"], "synthetic/epoch");
    assert_eq!(status["state"]["remainders"], json!({}));
    assert_eq!(fs::metadata(directory).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o600);

    fs::remove_file(directory.join("state.json.lock")).unwrap();
    run(&["--traffic-check"], true);
    run(&["--traffic-status"], true);
    assert!(!directory.join("state.json.lock").exists());
    run(&["--traffic-init", seed.to_str().unwrap()], false);
    assert_eq!(fs::read(&state).unwrap(), before);

    fs::write(&state, "{invalid").unwrap();
    run(&["--traffic-status"], false);
    assert_eq!(fs::read_to_string(&state).unwrap(), "{invalid");
}
