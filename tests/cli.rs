//! End-to-end tests of the `sentinel-fim` binary.

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

/// A scratch area with a `data/` directory to monitor.
struct Env {
    dir: TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Env {
            dir: TempDir::new().unwrap(),
        };
        fs::create_dir_all(env.data().join("sub")).unwrap();
        env.write("a.txt", "abc");
        env.write("sub/b.txt", "bbb");
        env
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn data(&self) -> PathBuf {
        self.path("data")
    }

    fn write(&self, rel: &str, contents: &str) {
        fs::write(self.data().join(rel), contents).unwrap();
    }

    fn baseline(&self) -> PathBuf {
        self.path("baseline.json")
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("sentinel-fim").unwrap();
        cmd.current_dir(self.dir.path())
            .env_remove("SENTINEL_FIM_LOG");
        cmd
    }

    fn init(&self, extra: &[&str]) {
        self.cmd()
            .arg("init")
            .arg(self.data())
            .arg("-b")
            .arg(self.baseline())
            .args(extra)
            .assert()
            .success();
    }

    fn scan_json(&self) -> (i32, Value) {
        let out = self
            .cmd()
            .args(["scan", "--format", "json", "-b"])
            .arg(self.baseline())
            .output()
            .unwrap();
        let json = serde_json::from_slice(&out.stdout).expect("stdout is pure JSON");
        (out.status.code().unwrap(), json)
    }
}

fn changes(report: &Value) -> Vec<(String, String)> {
    report["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["path"].as_str().unwrap().to_owned(),
                c["kind"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn help_documents_exit_codes() {
    Command::cargo_bin("sentinel-fim")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Exit codes:"))
        .stdout(predicate::str::contains("4  the baseline was rejected"));
}

#[test]
fn usage_error_exits_2() {
    Command::cargo_bin("sentinel-fim")
        .unwrap()
        .args(["scan", "--no-such-flag"])
        .assert()
        .code(2);
}

#[test]
fn clean_scan_exits_0() {
    let env = Env::new();
    env.init(&[]);
    env.cmd()
        .arg("scan")
        .arg("-b")
        .arg(env.baseline())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Result: CLEAN"));
}

#[test]
fn changes_exit_1_and_are_listed() {
    let env = Env::new();
    env.init(&[]);
    env.write("a.txt", "modified");
    env.write("new.txt", "");
    fs::remove_file(env.data().join("sub/b.txt")).unwrap();

    let (code, report) = env.scan_json();
    assert_eq!(code, 1);
    assert_eq!(report["status"], "changed");
    assert_eq!(
        changes(&report),
        [
            ("a.txt".into(), "modified".into()),
            ("new.txt".into(), "added".into()),
            ("sub/b.txt".into(), "removed".into()),
        ]
    );
}

#[test]
fn json_stdout_stays_clean_with_verbose_logging() {
    let env = Env::new();
    env.init(&[]);
    let out = env
        .cmd()
        .args(["-vvv", "scan", "--format", "json", "-b"])
        .arg(env.baseline())
        .output()
        .unwrap();
    serde_json::from_slice::<Value>(&out.stdout).expect("logs must not reach stdout");
    assert!(!out.stderr.is_empty(), "logs go to stderr");
}

#[test]
fn excludes_are_recorded_in_the_baseline() {
    let env = Env::new();
    env.write("debug.log", "x");
    env.init(&["--exclude", "*.log"]);
    // Changes to excluded files are invisible to later scans.
    env.write("debug.log", "changed");
    env.write("other.log", "new");
    let (code, report) = env.scan_json();
    assert_eq!(code, 0, "{report}");
}

#[test]
fn baseline_inside_root_is_excluded_automatically() {
    let env = Env::new();
    let inside = env.data().join("baseline.json");
    env.cmd()
        .arg("init")
        .arg(env.data())
        .arg("-b")
        .arg(&inside)
        .assert()
        .success()
        .stderr(predicate::str::contains("inside the scanned directory"));
    env.cmd()
        .arg("scan")
        .arg("-b")
        .arg(&inside)
        .assert()
        .code(0);
}

#[test]
fn init_refuses_to_overwrite_without_force() {
    let env = Env::new();
    env.init(&[]);
    env.cmd()
        .arg("init")
        .arg(env.data())
        .arg("-b")
        .arg(env.baseline())
        .assert()
        .code(3)
        .stderr(predicate::str::contains("already exists"));
    env.init(&["--force"]);
}

#[test]
fn missing_root_is_an_error() {
    let env = Env::new();
    env.cmd()
        .arg("init")
        .arg(env.path("nope"))
        .arg("-b")
        .arg(env.baseline())
        .assert()
        .code(3);
    assert!(!env.baseline().exists());
}

#[test]
fn tampered_baseline_exits_4() {
    let env = Env::new();
    env.init(&[]);
    let text = fs::read_to_string(env.baseline()).unwrap();
    fs::write(
        env.baseline(),
        text.replacen("\"size\": 3", "\"size\": 4", 1),
    )
    .unwrap();

    for command in ["scan", "verify"] {
        env.cmd()
            .arg(command)
            .arg("-b")
            .arg(env.baseline())
            .assert()
            .code(4)
            .stderr(predicate::str::contains("checksum mismatch"));
    }
}

#[test]
fn garbage_baseline_exits_4() {
    let env = Env::new();
    fs::write(env.baseline(), "{ not json").unwrap();
    env.cmd()
        .arg("verify")
        .arg("-b")
        .arg(env.baseline())
        .assert()
        .code(4)
        .stderr(predicate::str::contains("malformed"));
}

#[test]
fn missing_baseline_exits_3() {
    let env = Env::new();
    env.cmd()
        .arg("scan")
        .arg("-b")
        .arg(env.baseline())
        .assert()
        .code(3)
        .stderr(predicate::str::contains("cannot read baseline"));
}

#[test]
fn signing_workflow() {
    let env = Env::new();
    let (secret, public) = (env.path("k.secret"), env.path("k.pub"));
    env.cmd()
        .arg("keygen")
        .arg("--secret-key")
        .arg(&secret)
        .arg("--public-key")
        .arg(&public)
        .assert()
        .success();
    // Keys are never overwritten.
    env.cmd()
        .arg("keygen")
        .arg("--secret-key")
        .arg(&secret)
        .arg("--public-key")
        .arg(env.path("other.pub"))
        .assert()
        .code(3);

    env.init(&[]);
    let verify = |extra: &[&str]| {
        let mut cmd = env.cmd();
        cmd.arg("verify").arg("-b").arg(env.baseline()).args(extra);
        cmd
    };
    let public_arg = public.to_str().unwrap();
    verify(&["--require-signature"]).assert().code(4);
    verify(&["--public-key", public_arg]).assert().code(4);

    env.cmd()
        .arg("sign")
        .arg("-b")
        .arg(env.baseline())
        .arg("--secret-key")
        .arg(&secret)
        .assert()
        .success();
    verify(&["--public-key", public_arg, "--require-signature"])
        .assert()
        .success()
        .stdout(predicate::str::contains("signature:  verified"));

    // A forged baseline with a recomputed checksum fails the signature.
    let mut json: Value =
        serde_json::from_str(&fs::read_to_string(env.baseline()).unwrap()).unwrap();
    let body = json["body"]
        .to_string()
        .replacen("\"size\":3", "\"size\":4", 1);
    let digest = sha256_hex(body.as_bytes());
    json["body_sha256"] = Value::String(digest);
    let forged = format!(
        "{{\"format\":{},\"version\":1,\"body_sha256\":{},\"signature\":{},\"body\":{body}}}",
        json["format"], json["body_sha256"], json["signature"]
    );
    fs::write(env.baseline(), forged).unwrap();
    verify(&["--public-key", public_arg])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("signature does not verify"));
}

#[test]
fn init_can_sign_directly() {
    let env = Env::new();
    let (secret, public) = (env.path("k.secret"), env.path("k.pub"));
    env.cmd()
        .arg("keygen")
        .arg("--secret-key")
        .arg(&secret)
        .arg("--public-key")
        .arg(&public)
        .assert()
        .success();
    env.init(&["--sign-key", secret.to_str().unwrap()]);
    env.cmd()
        .arg("scan")
        .arg("-b")
        .arg(env.baseline())
        .arg("--public-key")
        .arg(&public)
        .arg("--require-signature")
        .assert()
        .code(0);
}

#[test]
fn saved_report_can_be_rendered_again() {
    let env = Env::new();
    env.init(&[]);
    env.write("a.txt", "changed");
    let report = env.path("report.json");
    env.cmd()
        .arg("scan")
        .arg("-b")
        .arg(env.baseline())
        .arg("--report")
        .arg(&report)
        .assert()
        .code(1);

    env.cmd()
        .arg("report")
        .arg(&report)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("~ modified     a.txt"));
    let out = env
        .cmd()
        .args(["report", "--format", "json"])
        .arg(&report)
        .output()
        .unwrap();
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["summary"]["modified"], 1);

    fs::write(&report, "{}").unwrap();
    env.cmd().arg("report").arg(&report).assert().code(3);
}

#[test]
fn verify_json_output() {
    let env = Env::new();
    env.init(&[]);
    let out = env
        .cmd()
        .args(["verify", "--format", "json", "-b"])
        .arg(env.baseline())
        .output()
        .unwrap();
    assert!(out.status.success());
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["valid"], true);
    assert_eq!(json["entries"], 3);
    assert_eq!(json["signature"], "unsigned");
}

#[test]
fn configuration_file() {
    let env = Env::new();
    env.write("x.tmp", "");
    let config = env.path("sentinel.toml");
    fs::write(
        &config,
        "root = \"data\"\nbaseline = \"from-config.json\"\nexclude = [\"*.tmp\"]\n",
    )
    .unwrap();

    env.cmd()
        .arg("--config")
        .arg(&config)
        .arg("init")
        .assert()
        .success();
    assert!(env.path("from-config.json").exists());
    env.write("x.tmp", "changed");
    env.cmd()
        .arg("-c")
        .arg(&config)
        .arg("scan")
        .assert()
        .code(0);

    fs::write(&config, "exclud = [\"*.tmp\"]\n").unwrap();
    env.cmd()
        .arg("-c")
        .arg(&config)
        .arg("scan")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("invalid configuration"));
}

#[test]
fn no_baseline_path_is_an_error() {
    let env = Env::new();
    env.cmd()
        .arg("scan")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no baseline file given"));
}

#[test]
fn watch_reports_changes_and_exits_1() {
    let env = Env::new();
    env.init(&[]);
    let data = env.data();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        fs::write(data.join("a.txt"), "tampered").unwrap();
    });
    let out = env
        .cmd()
        .args([
            "watch",
            "--format",
            "json",
            "--duration",
            "4",
            "--debounce",
            "100",
            "-b",
        ])
        .arg(env.baseline())
        .output()
        .unwrap();
    writer.join().unwrap();

    let events: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("every line is JSON"))
        .collect();
    assert_eq!(events.first().unwrap()["event"], "started");
    assert!(
        events
            .iter()
            .any(|e| e["event"] == "change" && e["path"] == "a.txt" && e["kind"] == "modified"),
        "{events:?}"
    );
    assert_eq!(events.last().unwrap()["event"], "stopped");
    assert_eq!(out.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn init_refuses_incomplete_scan_unless_allowed() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let locked = env.data().join("sub");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(&locked).is_ok() {
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        eprintln!("SKIPPED: running as root, permissions are not enforced");
        return;
    }

    env.cmd()
        .arg("init")
        .arg(env.data())
        .arg("-b")
        .arg(env.baseline())
        .assert()
        .code(3)
        .stderr(predicate::str::contains("could not be read"));
    assert!(!env.baseline().exists());

    env.cmd()
        .arg("init")
        .arg(env.data())
        .arg("-b")
        .arg(env.baseline())
        .arg("--allow-incomplete")
        .assert()
        .code(3);
    assert!(env.baseline().exists());
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn unreadable_file_makes_scan_incomplete_not_removed() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    env.init(&[]);
    let file = env.data().join("a.txt");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&file).is_ok() {
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        eprintln!("SKIPPED: running as root, permissions are not enforced");
        return;
    }

    let (code, report) = env.scan_json();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(code, 3);
    assert_eq!(report["status"], "incomplete");
    assert_eq!(report["unverified"], serde_json::json!(["a.txt"]));
    assert_eq!(report["issues"][0]["code"], "permission_denied");
    assert!(changes(&report).is_empty());
}

fn sha256_hex(data: &[u8]) -> String {
    use sentinel_fim::hash::Algorithm;
    let mut reader = data;
    Algorithm::Sha256
        .hash_reader(&mut reader)
        .unwrap()
        .digest
        .to_string()
}
