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
        darwinBuildEnv = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
          # The processed Nix SDK omits libiconv. Use Apple's original stubs so
          # profile-installed tools link system libraries without Nix dylibs.
          export SDKROOT=${pkgs.apple-sdk.src}
          export MACOSX_DEPLOYMENT_TARGET=11.0
          export CC=${pkgs.llvmPackages.clang-unwrapped}/bin/clang
          export CXX=${pkgs.llvmPackages.clang-unwrapped}/bin/clang++
          export AR=${pkgs.llvmPackages.llvm}/bin/llvm-ar
          export CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER="$CC"
          export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="$CC"
        '';
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
