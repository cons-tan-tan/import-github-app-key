{
  perSystem =
    { pkgs, ... }:
    let
      source = pkgs.lib.fileset.toSource {
        root = ../.;
        fileset = ../.github;
      };
    in
    {
      checks.workflows =
        pkgs.runCommand "workflow-check"
          {
            nativeBuildInputs = [ pkgs.zizmor ];
          }
          ''
            zizmor --offline --strict-collection ${source}/.github
            touch "$out"
          '';
    };
}
