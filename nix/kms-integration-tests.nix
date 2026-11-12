{
  perSystem =
    { pkgs, rustToolchains, ... }:
    let
      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustToolchains.native;
        rustc = rustToolchains.native;
      };
    in
    {
      packages.kms-integration-tests = rustPlatform.buildRustPackage {
        pname = "kms-integration-tests";
        version = "0.1.0";
        src = pkgs.lib.fileset.toSource {
          root = ../.;
          fileset = pkgs.lib.fileset.unions [
            ../Cargo.toml
            ../src
            ../testdata
            ../integration-tests/kms/Cargo.toml
            ../integration-tests/kms/Cargo.lock
            ../integration-tests/kms/tests
          ];
        };
        cargoRoot = "integration-tests/kms";
        buildAndTestSubdir = "integration-tests/kms";
        cargoLock = {
          lockFile = ../integration-tests/kms/Cargo.lock;
          outputHashes."aws-emulator-engine-0.1.0" = "sha256-PIKq0qJkdIdS+0Hq81jmKv0QF8ouKXWuc6BhFtCZngQ=";
        };
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.pkg-config
        ];
        nativeCheckInputs = [ pkgs.cacert ];
        buildType = "debug";
        dontBuild = true;
        cargoTestFlags = [ "--locked" ];
        env.EMULATOR_TELEMETRY = "off";
        # Large AWS SDK crates need several GiB per compiler process.
        preCheck = ''
          NIX_BUILD_CORES=$((NIX_BUILD_CORES < 2 ? NIX_BUILD_CORES : 2))
        '';
        installPhase = ''
          runHook preInstall
          touch "$out"
          runHook postInstall
        '';
        meta.description = "Test key import and signing against an in-memory AWS KMS emulator";
      };
    };
}
