{
  description = "Import GitHub App private keys into a cloud KMS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs =
    {
      self,
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
          default = pkgs.buildGoModule {
            pname = "import-github-app-key";
            inherit version;
            src = ./.;
            vendorHash = "sha256-77O7Dpt82iz4eDMmijpsJNeKoUBd93O6boplMRUD3fY=";
            ldflags = [
              "-s"
              "-w"
              "-X main.version=${version}"
            ];
            checkFlags = [ "-race" ];
            meta = {
              description = "Import GitHub App private keys into AWS KMS";
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
            description = "Import GitHub App private keys into AWS KMS";
          };
        };
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go
              gopls
              goreleaser
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
