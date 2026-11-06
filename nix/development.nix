{
  perSystem =
    {
      config,
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
        ];
        pathsToLink = [ "/bin" ];
      };

      devShells.default = pkgs.mkShell {
        packages = [
          config.packages.ci-tools
          pkgs.cargo-audit
          pkgs.rust-analyzer
          config.treefmt.build.wrapper
        ];
      };
    };
}
