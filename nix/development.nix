{
  perSystem =
    {
      config,
      darwinBuildEnv,
      pkgs,
      rustToolchains,
      ...
    }:
    {
      packages.ci-tools = pkgs.buildEnv {
        name = "import-github-app-key-ci-tools";
        paths = [
          rustToolchains.native
          pkgs.stdenv.cc
          pkgs.cmake
          pkgs.pkg-config
        ]
        ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
          (pkgs.lib.hiPrio (
            pkgs.writeShellScriptBin "cargo" ''
              ${darwinBuildEnv}
              exec ${rustToolchains.native}/bin/cargo "$@"
            ''
          ))
        ];
        pathsToLink = [ "/bin" ];
      };

      devShells.default = pkgs.mkShell {
        packages = [
          config.packages.ci-tools
          pkgs.cargo-audit
          pkgs.gh-actions-lock
          pkgs.rust-analyzer
          config.treefmt.build.wrapper
        ];
      };
    };
}
