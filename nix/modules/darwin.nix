# SPEC §8.3: root launchd service and an hourly, finite logrotate job.
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
  rotation = pkgs.writeText "z53-logrotate.conf" ''
    /var/log/z53.log {
      daily
      maxsize 10M
      rotate 7
      missingok
      notifempty
      copytruncate
      compress
    }
  '';
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
    environment.etc."z53/logrotate.conf".source = rotation;
    launchd.daemons.z53.serviceConfig = {
      # launchd execs ProgramArguments at load and never retries a failed exec,
      # even with KeepAlive. If the Nix store volume is not mounted yet, the
      # job parks permanently and only a manual kickstart or reboot recovers
      # it. Waiting for the store keeps the job alive as a shell until the
      # executable path exists, and a later exec failure inside the shell
      # exits with a real status that KeepAlive does restart.
      ProgramArguments = [
        "/bin/sh"
        "-c"
        "/bin/wait4path /nix/store && exec ${lib.getExe cfg.package} -c /etc/z53/z53.zon"
      ];
      # The content-addressed path changes the plist so a switch reloads the job.
      EnvironmentVariables.Z53_CONFIG_SOURCE = "${configFile}";
      UserName = "root";
      RunAtLoad = true;
      KeepAlive = true;
      StandardOutPath = "/var/log/z53.log";
      StandardErrorPath = "/var/log/z53.log";
    };
    launchd.daemons.z53-logrotate.serviceConfig = {
      # The same store-volume guard as the resolver. See the comment above.
      ProgramArguments = [
        "/bin/sh"
        "-c"
        "/bin/wait4path /nix/store && exec ${lib.getExe pkgs.logrotate} --state /var/log/z53-logrotate.status /etc/z53/logrotate.conf"
      ];
      UserName = "root";
      StartInterval = 3600;
    };
  };
}
