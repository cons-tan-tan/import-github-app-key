{
  perSystem =
    { pkgs, ... }:
    let
      checkReleaseBinary = pkgs.writeShellApplication {
        name = "check-release-binary";
        runtimeInputs = [
          pkgs.llvmPackages.llvm
          pkgs.coreutils
          pkgs.gnugrep
          pkgs.gnused
          pkgs.file
        ];
        inheritPath = false;
        text = ''
          target=''${1:?Usage: check-release-binary TARGET BINARY}
          binary=''${2:?Usage: check-release-binary TARGET BINARY}
          test -s "$binary"

          case "$target" in
            x86_64-unknown-linux-gnu) format=elf64-x86-64 ;;
            aarch64-unknown-linux-gnu) format=elf64-littleaarch64 ;;
            x86_64-apple-darwin) format='Mach-O 64-bit x86-64' ;;
            aarch64-apple-darwin) format='Mach-O arm64' ;;
            x86_64-pc-windows-msvc) format=COFF-x86-64 ;;
            aarch64-pc-windows-msvc) format=COFF-ARM64 ;;
            *) echo "Unsupported release target: $target" >&2; exit 1 ;;
          esac
          headers=$(llvm-readobj --file-headers "$binary")
          if ! grep -Fxq "Format: $format" <<< "$headers"; then
            echo "Release binary does not match target $target: $binary" >&2
            exit 1
          fi

          case "$target" in
            *-unknown-linux-gnu)
              linkage=$(llvm-readelf --program-headers --dynamic "$binary")
              # Nix-built tools may run from /nix/store; distributed binaries must not.
              if [[ "$linkage" == *'/nix/store/'* ]]; then
                echo "Release binary has a Nix runtime dependency: $binary" >&2
                exit 1
              fi
              case "$target" in
                x86_64-*) interpreter=/lib64/ld-linux-x86-64.so.2 ;;
                aarch64-*) interpreter=/lib/ld-linux-aarch64.so.1 ;;
              esac
              if ! grep -Fxq "      [Requesting program interpreter: $interpreter]" <<< "$linkage"; then
                echo "Unexpected Linux dynamic linker: $binary" >&2
                exit 1
              fi
              required=$(llvm-readelf --version-info "$binary" | sed -nE 's/.*Name: GLIBC_([0-9.]+).*/\1/p' | sort -Vu | tail -n 1)
              if [[ -z "$required" || "$(printf '%s\n' "$required" 2.35 | sort -V | tail -n 1)" != 2.35 ]]; then
                echo "Release binary exceeds the glibc 2.35 baseline: ''${required:-unknown}" >&2
                exit 1
              fi
              ;;
            *-apple-darwin)
              linkage=$(llvm-objdump --macho --dylibs-used --rpaths "$binary")
              if [[ "$linkage" == *'/nix/store/'* ]]; then
                echo "Release binary has a Nix runtime dependency: $binary" >&2
                exit 1
              fi
              ;;
            *-pc-windows-msvc)
              imports=$(llvm-readobj --coff-imports "$binary")
              if grep -Eiq 'Name: (vcruntime|msvcp|ucrtbase)[^ ]*\.dll' <<< "$imports"; then
                echo "Release binary requires a separately installed MSVC runtime: $binary" >&2
                exit 1
              fi
              ;;
          esac
          file "$binary"
        '';
      };
    in
    {
      packages.check-release-binary = checkReleaseBinary;
      packages.test-release-binary = pkgs.writeShellApplication {
        name = "test-release-binary";
        inheritPath = false;
        text = ''
          target=''${1:?Usage: test-release-binary TARGET BINARY}
          binary=''${2:?Usage: test-release-binary TARGET BINARY}
          checker=${pkgs.lib.getExe checkReleaseBinary}

          "$checker" "$target" "$binary"

          case "$target" in
            x86_64-*) wrong_arch=aarch64 ;;
            aarch64-*) wrong_arch=x86_64 ;;
          esac
          case "$target" in
            *-windows-*) wrong_os=unknown-linux-gnu ;;
            *) wrong_os=pc-windows-msvc ;;
          esac
          for wrong_target in "$wrong_arch-''${target#*-}" "''${target%%-*}-$wrong_os"; do
            if "$checker" "$wrong_target" "$binary"; then
              echo "Binary check accepted $binary for $wrong_target" >&2
              exit 1
            fi
          done
        '';
      };
    };
}
