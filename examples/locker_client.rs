//! Reference lock-UI client for the `lion-locker` socket protocol (v1).
//!
//! Plays the role of `lion-lockscreen`: connects, waits for `Show`,
//! authenticates with a password, and prints every event it sees.
//!
//! ```text
//! lion-locker --mock &                       # demo daemon (password: lion)
//! cargo run --example locker_client -- "$XDG_RUNTIME_DIR/lion-locker/ui.sock" lion
//! ```
//!
//! Real UIs must (1) retry connecting until the socket accepts them (the
//! daemon admits only its own supervised child), (2) ignore unknown event
//! fields, (3) never log or persist the password.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

fn send(w: &mut impl Write, id: u64, mut body: Value) {
    body["proto"] = 1.into();
    body["id"] = id.into();
    writeln!(w, "{body}").expect("write request");
}

/// Same resolution order as the daemon: `$XDG_RUNTIME_DIR`, else the
/// logind-managed `/run/user/<uid>` — never `/tmp`.
fn default_socket_path() -> String {
    let base = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| format!("/run/user/{}", lion_locker::sysffi::getuid()));
    format!("{base}/lion-locker/ui.sock")
}

fn main() {
    let mut args = std::env::args().skip(1);
    let sock = args.next().unwrap_or_else(default_socket_path);
    let password = args.next().unwrap_or_else(|| "lion".into());

    // Retry: the daemon refuses connections while it has no UI to admit.
    let stream = (0..50)
        .find_map(|_| {
            UnixStream::connect(&sock).ok().or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(100));
                None
            })
        })
        .unwrap_or_else(|| {
            eprintln!("cannot connect to {sock}");
            std::process::exit(1)
        });
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);

    let mut began = false;
    let mut sent_answer = false;
    let mut line = String::new();
    loop {
        line.clear();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            println!("daemon closed the connection");
            return;
        }
        let v: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        println!("<- {v}");
        match v["event"].as_str() {
            Some("Show") if !began => {
                began = true;
                send(&mut w, 1, json!({"op": "Begin"}));
            }
            Some("Prompt") if v["kind"] == "secret" && !sent_answer => {
                sent_answer = true;
                send(&mut w, 2, json!({"op": "Answer", "text": password}));
            }
            Some("AuthResult") => {
                if v["ok"] == true {
                    println!("unlocked");
                } else {
                    println!("authentication failed: {}", v["reason"]);
                }
                return;
            }
            Some("Hide") => return,
            _ => {}
        }
    }
}
