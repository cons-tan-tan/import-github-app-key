{ inputs, ... }:
{
  imports = [ inputs.treefmt-nix.flakeModule ];

  perSystem.treefmt = {
    projectRootFile = "flake.nix";
    programs.rustfmt.enable = true;
    programs.nixfmt.enable = true;
    programs.yamlfmt = {
      enable = true;
      settings.formatter.retain_line_breaks_single = true;
    };
  };
}
