{
  description = "Import GitHub App private keys into a cloud KMS";

  inputs = {
    go1264-src = {
      url = "https://go.dev/dl/go1.26.4.src.tar.gz";
      flake = false;
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs =
    {
      self,
      go1264-src,
      nixpkgs,
      treefmt-nix,
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      version = "0-unstable-${self.shortRev or self.dirtyShortRev or "unknown"}";
      go1264For =
        pkgs:
        pkgs.go_1_26.overrideAttrs {
          version = "1.26.4";
          src = go1264-src;
        };
      treefmtEval = forAllSystems (
        system:
        treefmt-nix.lib.evalModule nixpkgs.legacyPackages.${system} {
          projectRootFile = "flake.nix";
          programs.gofmt.enable = true;
          programs.nixfmt.enable = true;
          programs.yamlfmt = {
            enable = true;
            settings.formatter.retain_line_breaks_single = true;
          };
        }
      );
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = (pkgs.buildGoModule.override { go = go1264For pkgs; }) {
            pname = "import-github-app-key";
            inherit version;
            src = ./.;
            vendorHash = "sha256-vBll6QYZZ4NZs/c9wtdX7H/vLxFWP16rM8dtn0sm85Q=";
            ldflags = [
              "-s"
              "-w"
              "-X main.version=${version}"
            ];
            checkFlags = [ "-race" ];
            meta = {
              description = "Import GitHub App private keys into AWS KMS or Google Cloud KMS";
              mainProgram = "import-github-app-key";
            };
          };
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/import-github-app-key";
          meta = {
            description = "Import GitHub App private keys into AWS KMS or Google Cloud KMS";
          };
        };
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          go1264 = go1264For pkgs;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go1264
              gopls
              goreleaser
              go-tools # staticcheck
              govulncheck
              treefmtEval.${system}.config.build.wrapper
            ];
          };
        }
      );

      formatter = forAllSystems (system: treefmtEval.${system}.config.build.wrapper);

      checks = forAllSystems (system: {
        formatting = treefmtEval.${system}.config.build.check self;
      });
    };
}
