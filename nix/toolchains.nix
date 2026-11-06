{ inputs, ... }:
{
  perSystem =
    { system, ... }:
    let
      pkgs = import inputs.nixpkgs {
        inherit system;
        overlays = [ inputs.rust-overlay.overlays.default ];
      };
      toolchainConfig = (builtins.fromTOML (builtins.readFile ../rust-toolchain.toml)).toolchain;
    in
    {
      _module.args = {
        inherit pkgs;
        rustToolchains = {
          native = pkgs.rust-bin.fromRustupToolchain toolchainConfig;
          release = pkgs.rust-bin.fromRustupToolchain (
            toolchainConfig
            // {
              targets =
                if pkgs.stdenv.hostPlatform.isDarwin then
                  [
                    "x86_64-apple-darwin"
                    "aarch64-apple-darwin"
                  ]
                else
                  [
                    "x86_64-unknown-linux-gnu"
                    "aarch64-unknown-linux-gnu"
                    "x86_64-pc-windows-msvc"
                    "aarch64-pc-windows-msvc"
                  ];
            }
          );
        };
      };
    };
}
