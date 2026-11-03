# kubernix overlay for the containerd e2e tests.
#
# kubernix disables NRI in the containerd config it generates and starts
# containerd right after writing it, so the config cannot be patched from
# the outside without racing containerd. This overlay wraps containerd to
# enable NRI in the file passed via --config before containerd reads it.
self: super:
let
  wrapper = super.writeShellScript "containerd" ''
    for arg in "$@"; do
      case "$arg" in
      --config=*)
        ${super.gnused}/bin/sed -i \
          '/^\[plugins\."io\.containerd\.nri\.v1\.nri"\]$/,/^\[/ s/^disable = true$/disable = false/' \
          "''${arg#--config=}"
        ;;
      esac
    done
    exec ${super.containerd}/bin/containerd "$@"
  '';
in
{
  containerd = super.symlinkJoin {
    name = "containerd-nri-${super.containerd.version}";
    paths = [ super.containerd ];
    postBuild = ''
      rm "$out/bin/containerd"
      cp ${wrapper} "$out/bin/containerd"
    '';
  };
}
