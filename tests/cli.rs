use clap::Parser;
use import_github_app_key::cli::Cli;

#[test]
fn cli_preserves_flags_and_rejects_invalid_combinations() {
    for flags in [
        vec![],
        vec!["-d", "-v", "12345"],
        vec!["--dry-run"],
        vec!["--provider", "gcp", "--gcp-import-job", "projects/p/jobs/j"],
    ] {
        let mut args = vec!["import-github-app-key", "key", "testdata/pkcs1.pem"];
        args.extend(flags);
        Cli::try_parse_from(args).unwrap().validate().unwrap();
    }
    for flags in [
        vec!["--verify", "0"],
        vec!["--verify", "-1"],
        vec!["--dry-run", "--delete"],
        vec!["--dry-run", "--verify", "12345"],
        vec!["--provider", "unknown"],
    ] {
        let mut args = vec!["import-github-app-key", "key", "testdata/pkcs1.pem"];
        args.extend(flags);
        assert!(Cli::try_parse_from(args).is_err());
    }
    for flags in [vec!["--gcp-import-job", "job"], vec!["--provider", "gcp"]] {
        let mut args = vec!["import-github-app-key", "key", "testdata/pkcs1.pem"];
        args.extend(flags);
        assert!(Cli::try_parse_from(args).unwrap().validate().is_err());
    }
}

#[test]
fn verification_rejects_unsafe_urls_before_cloud_initialization() {
    for url in [
        "http://api.github.com",
        "http://127.0.0.1:8080",
        "https://user:password@example.com",
        "https://example.com?token=secret",
        "https://example.com#fragment",
        "file:///tmp/app",
        "not a URL",
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_import-github-app-key"))
            .args([
                "--verify",
                "12345",
                "--github-url",
                url,
                "key",
                "testdata/pkcs1.pem",
            ])
            .env_clear()
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.contains("GitHub") || error.contains("github-url"),
            "{error}"
        );
        assert!(!error.contains("password") && !error.contains("secret"));
    }
    for url in [
        "https://api.github.com",
        "https://github.example.com/api/v3/",
    ] {
        Cli::try_parse_from([
            "import-github-app-key",
            "--verify",
            "12345",
            "--github-url",
            url,
            "key",
            "testdata/pkcs1.pem",
        ])
        .unwrap()
        .validate()
        .unwrap();
    }
}

#[test]
fn executable_help_and_version_need_no_credentials() {
    for flag in ["--help", "--version"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_import-github-app-key"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("import-github-app-key")
        );
    }
}
