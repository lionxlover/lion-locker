//! Fuzz smoke (spec 03 §10): deterministic mutation corpus through the
//! same entry points the cargo-fuzz targets use, so `cargo test` catches
//! decoder/config panics without a nightly toolchain.
use lion_locker::proto::{decode_request, Request};
use lion_locker::Config;

/// xorshift64* — deterministic, dependency-free.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const SEEDS: &[&str] = &[
    r#"{"proto":1,"id":1,"op":"Hello"}"#,
    r#"{"proto":1,"id":2,"op":"Begin"}"#,
    r#"{"proto":1,"id":3,"op":"Answer","text":"hunter2"}"#,
    r#"{"proto":1,"id":4,"op":"Cancel"}"#,
    r#"{"proto":1,"id":5,"op":"GraceUnlock"}"#,
    r#"{"proto":1,"id":6,"op":"Action","action":"shutdown"}"#,
    r#"{"locker":{"grace_period_ms":500,"pam":{"service":"lion-locker"}}}"#,
];

fn mutate(rng: &mut Rng, seed: &str) -> String {
    let mut b: Vec<u8> = seed.as_bytes().to_vec();
    for _ in 0..1 + rng.below(6) {
        if b.is_empty() {
            b.push(b'{');
        }
        match rng.below(5) {
            0 => {
                let i = rng.below(b.len());
                b[i] = rng.next() as u8;
            }
            1 => {
                let i = rng.below(b.len());
                b.remove(i);
            }
            2 => {
                let i = rng.below(b.len() + 1);
                b.insert(i, rng.next() as u8);
            }
            3 => {
                let i = rng.below(b.len());
                let n = rng.below(b.len() - i + 1);
                let chunk: Vec<u8> = b[i..i + n].to_vec();
                b.extend(chunk);
            }
            _ => {
                b.truncate(rng.below(b.len() + 1));
            }
        }
    }
    String::from_utf8_lossy(&b).into_owned()
}

#[test]
fn decoder_survives_mutation_corpus() {
    let mut rng = Rng(0x1ee7_c0de_dead_beef);
    let mut accepted = 0u32;
    for i in 0..60_000 {
        let s = mutate(&mut rng, SEEDS[i % SEEDS.len()]);
        match decode_request(&s) {
            Ok(Request::Answer { text, .. }) => {
                accepted += 1;
                assert!(text.as_str().len() <= 1024 && !text.as_str().contains('\0'));
            }
            Ok(_) => accepted += 1,
            Err(e) => assert!(e.to_wire().len() < 600),
        }
    }
    // Sanity: the corpus exercises both outcomes.
    assert!(accepted > 100, "mutations never produced a valid request");
}

#[test]
fn config_loader_survives_mutation_corpus() {
    let mut rng = Rng(0xfeed_face_cafe_f00d);
    for i in 0..30_000 {
        let s = mutate(&mut rng, SEEDS[i % SEEDS.len()]);
        if let Ok(c) = Config::parse(&s) {
            c.validate().expect("parsed configs always validate");
        }
    }
}

#[test]
fn pathological_inputs() {
    let deep = format!("{}1{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(decode_request(&deep).is_err());
    assert!(Config::parse(&deep).is_err());
    let long = format!(
        r#"{{"proto":1,"id":1,"op":"Answer","text":"{}"}}"#,
        "é".repeat(5_000)
    );
    assert!(decode_request(&long).is_err());
    for s in ["", "{", "}", "null", "\u{0}", "{\"proto\":1}", "[]"] {
        assert!(decode_request(s).is_err(), "{s:?}");
    }
}
