# SPEC §8.2: the module does not change another resolver or host DNS policy.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.z53;
  configFile = pkgs.writeText "z53.zon" cfg.config;
in
{
  options.services.z53 = {
    enable = lib.mkEnableOption "z53";
    config = lib.mkOption {
      type = lib.types.lines;
      description = "Required ZON configuration. The text enters the Nix store and must not contain secrets.";
    };
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.z53;
      defaultText = lib.literalExpression "z53.packages.\${pkgs.stdenv.hostPlatform.system}.z53";
      description = "The z53 package.";
    };
  };
  config = lib.mkIf cfg.enable {
    environment.etc."z53/z53.zon".source = configFile;
    systemd.services.z53 = {
      description = "z53 DNS caching forwarder";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      restartTriggers = [ configFile ];
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} -c /etc/z53/z53.zon";
        DynamicUser = true;
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        Restart = "on-failure";
        LimitNOFILE = 1048576;
      };
    };
  };
}
