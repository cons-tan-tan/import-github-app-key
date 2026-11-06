{
  perSystem =
    {
      config,
      pkgs,
      rustToolchains,
      ...
    }:
    let
      lockedCargo = pkgs.writeShellScriptBin "cargo" ''
        # dist 0.34 does not pass --locked to its cargo build commands.
        case "''${1:-}" in
          build|metadata|zigbuild|xwin)
            for arg in "$@"; do
              case "$arg" in
                --locked|--frozen) exec ${rustToolchains.release}/bin/cargo "$@" ;;
              esac
            done
            exec ${rustToolchains.release}/bin/cargo "$@" --locked
            ;;
          *) exec ${rustToolchains.release}/bin/cargo "$@" ;;
        esac
      '';
      releaseTools = [
        (pkgs.lib.hiPrio lockedCargo)
        rustToolchains.release
        (pkgs.lib.hiPrio pkgs.stdenv.cc)
        pkgs.cargo-dist
        pkgs.cargo-zigbuild
        pkgs.cargo-xwin
        pkgs.llvmPackages.clang-unwrapped
        pkgs.llvmPackages.llvm
        pkgs.llvmPackages.lld
        pkgs.nasm
        pkgs.cmake
        pkgs.ninja
        pkgs.pkg-config
        pkgs.git
        pkgs.cacert
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.gnused
        pkgs.gawk
        pkgs.findutils
        pkgs.gnutar
        pkgs.gzip
        pkgs.xz
        pkgs.zip
        pkgs.unzip
        pkgs.jq
        pkgs.file
        pkgs.gh
        pkgs.bash
      ];
      linuxLinker =
        target:
        pkgs.writeShellScript "${target}-cc" ''
          exec ${pkgs.cargo-zigbuild}/bin/cargo-zigbuild zig cc -- -fno-sanitize=all -target ${target}.2.35 "$@"
        '';
      releaseDist = pkgs.writeShellScriptBin "dist" ''
        # Exclude runner-installed rustup; all target stdlibs come from Nix.
        export PATH=${pkgs.lib.makeBinPath releaseTools}
        export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
        ${pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
          export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=${linuxLinker "x86_64-linux-gnu"}
          export CC_x86_64_unknown_linux_gnu=${linuxLinker "x86_64-linux-gnu"}
          export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=${linuxLinker "aarch64-linux-gnu"}
          export CC_aarch64_unknown_linux_gnu=${linuxLinker "aarch64-linux-gnu"}
          export XWIN_CROSS_COMPILER=clang-cl
          export XWIN_SDK_VERSION=10.0.26100
          export XWIN_CRT_VERSION=14.44.17.14
          export XWIN_CACHE_DIR="''${XDG_CACHE_HOME:-$HOME/.cache}/import-github-app-key-xwin-$XWIN_SDK_VERSION-$XWIN_CRT_VERSION"
        ''}
        ${pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
          export SDKROOT=${pkgs.apple-sdk}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk
          export MACOSX_DEPLOYMENT_TARGET=11.0
          export CC=${pkgs.llvmPackages.clang-unwrapped}/bin/clang
          export CXX=${pkgs.llvmPackages.clang-unwrapped}/bin/clang++
          export AR=${pkgs.llvmPackages.llvm}/bin/llvm-ar
          export CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER="$CC"
          export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="$CC"
        ''}
        exec ${pkgs.cargo-dist}/bin/dist "$@"
      '';
    in
    {
      packages.release-tools = pkgs.buildEnv {
        name = "import-github-app-key-release-tools";
        paths = [
          (pkgs.lib.hiPrio releaseDist)
          config.packages.check-release-binary
          config.packages.test-release-binary
        ]
        ++ releaseTools;
        pathsToLink = [ "/bin" ];
      };
    };
}
