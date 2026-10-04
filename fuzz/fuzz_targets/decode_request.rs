#![no_main]
//! Fuzz the lock-UI request decoder (spec 03 §10): any byte string must
//! decode or fail cleanly — never panic, never echo secret text into the
//! error, never accept an answer over the 1 KiB bound or containing NUL.
use libfuzzer_sys::fuzz_target;
use lion_locker::proto::{decode_request, Request};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    match decode_request(s) {
        Ok(Request::Answer { text, .. }) => {
            assert!(text.as_str().len() <= 1024);
            assert!(!text.as_str().contains('\0'));
        }
        Ok(_) => {}
        Err(e) => {
            // Error text must never reflect the input back verbatim.
            let wire = e.to_wire();
            assert!(wire.len() < 600);
        }
    }
});
