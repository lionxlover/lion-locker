#![no_main]
//! Fuzz the config loader: arbitrary text either parses to a config that
//! passes `validate()` or is rejected — never panics (fail closed).
use libfuzzer_sys::fuzz_target;
use lion_locker::Config;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(cfg) = Config::parse(s) {
        cfg.validate().expect("a parsed config must validate");
    }
});
