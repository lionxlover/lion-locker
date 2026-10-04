#![forbid(unsafe_code)]
//! Command-line parsing (spec 03 §9): `--version`, `--check-config`,
//! `--print-schema`, `--config PATH`, `--mock`. Pure parsing — no I/O —
//! so tests cover every path.

use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Args {
    pub config: Option<PathBuf>,
    pub version: bool,
    pub check_config: bool,
    pub print_schema: bool,
    /// All-fakes demo mode (no D-Bus, scripted services).
    pub mock: bool,
}

/// Parse from an argument vector (argv[1..]).
pub fn parse(args: &[String]) -> Result<Args, String> {
    let mut out = Args::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--version" | "-V" => out.version = true,
            "--check-config" => out.check_config = true,
            "--print-schema" => out.print_schema = true,
            "--mock" => out.mock = true,
            "--config" | "-c" => {
                i += 1;
                let Some(path) = args.get(i) else {
                    return Err("--config requires a path".into());
                };
                out.config = Some(PathBuf::from(path));
            }
            other => {
                return Err(format!(
                    "unknown argument {other:?} (expected --version, --check-config, --print-schema, --config PATH, --mock)"
                ));
            }
        }
        i += 1;
    }
    Ok(out)
}

/// Parse from `std::env::args()`.
pub fn from_env() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    parse(&argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Result<Args, String> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn empty_defaults() {
        assert_eq!(v(&[]).unwrap(), Args::default());
    }

    #[test]
    fn all_flags() {
        let a = v(&["--version", "--check-config", "--print-schema", "--mock"]).unwrap();
        assert!(a.version && a.check_config && a.print_schema && a.mock);
        assert!(a.config.is_none());
    }

    #[test]
    fn config_path() {
        let a = v(&["--config", "/etc/lion/locker.json"]).unwrap();
        assert_eq!(a.config, Some(PathBuf::from("/etc/lion/locker.json")));
        let a = v(&["-c", "/tmp/x.json"]).unwrap();
        assert_eq!(a.config, Some(PathBuf::from("/tmp/x.json")));
    }

    #[test]
    fn config_requires_value() {
        let e = v(&["--config"]).unwrap_err();
        assert!(e.contains("requires a path"));
    }

    #[test]
    fn unknown_argument_rejected() {
        let e = v(&["--frobnicate"]).unwrap_err();
        assert!(e.contains("unknown argument"));
    }

    #[test]
    fn version_short_flag() {
        assert!(v(&["-V"]).unwrap().version);
    }
}
