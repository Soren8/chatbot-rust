//! DNS sidecar unit tests.
//!
//! Given the repository's Python DNS sidecar, when unittest discovery runs
//! under `dns/`, then its forwarder and resolver unit tests execute and pass.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn dns_sidecar_python_unit_tests_pass() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let dns = root.join("dns");
    assert!(
        dns.join("tests").is_dir(),
        "dns/tests must exist at {}",
        dns.display()
    );

    let output = Command::new("python3")
        .args(["-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"])
        .current_dir(&dns)
        .output()
        .expect("python3 must be available in the tests image for DNS unit tests");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "DNS sidecar Python unit tests failed ({}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        dns.display()
    );

    let test_count = stderr
        .lines()
        .chain(stdout.lines())
        .find_map(|line| {
            line.strip_prefix("Ran ")
                .and_then(|line| line.split_whitespace().next())
                .and_then(|count| count.parse::<usize>().ok())
        })
        .expect("unittest output must report 'Ran N tests'");
    assert!(
        test_count > 0,
        "DNS sidecar unittest discovery ran zero tests:\n{stderr}\n{stdout}"
    );
    println!("DNS sidecar Python tests passed (Ran {test_count} tests):\n{stderr}");
}
