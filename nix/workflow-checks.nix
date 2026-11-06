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
            nativeBuildInputs = [
              pkgs.gh-actions-lock
              pkgs.zizmor
            ];
          }
          ''
            cd ${source}
            GH_ACTIONS_LOCK_REPO_ROOT=${source} gh-actions-lock --verify-local
            zizmor --offline --strict-collection --config ${source}/.github/zizmor.yml ${source}/.github
            touch "$out"
          '';
    };
}
