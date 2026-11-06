{ self, ... }:
{
  perSystem =
    {
      config,
      pkgs,
      rustToolchains,
      ...
    }:
    let
      version = "0-unstable-${self.shortRev or self.dirtyShortRev or "unknown"}";
      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustToolchains.native;
        rustc = rustToolchains.native;
      };
    in
    {
      packages.default = rustPlatform.buildRustPackage {
        pname = "import-github-app-key";
        inherit version;
        src = pkgs.lib.fileset.toSource {
          root = ../.;
          fileset = pkgs.lib.fileset.unions [
            ../Cargo.toml
            ../Cargo.lock
            ../src
            ../tests
            ../testdata
          ];
        };
        cargoLock.lockFile = ../Cargo.lock;
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.pkg-config
        ];
        nativeCheckInputs = [ pkgs.cacert ];
        APP_VERSION = version;
        meta = {
          description = "Import GitHub App private keys into AWS KMS or Google Cloud KMS";
          mainProgram = "import-github-app-key";
        };
      };

      apps.default = {
        type = "app";
        program = "${config.packages.default}/bin/import-github-app-key";
        meta.description = "Import GitHub App private keys into a cloud KMS";
      };
    };
}
