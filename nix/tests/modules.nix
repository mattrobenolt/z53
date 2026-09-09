# SPEC §8.2–8.4 and §9.5: evaluation only, without activation or listener creation.
{
  inputs,
  self,
  pkgs,
}:
let
  inherit (pkgs) lib;
  system = pkgs.stdenv.hostPlatform.system;
  isLinux = pkgs.stdenv.hostPlatform.isLinux;
  fixture = ''.{ .listen = .{"127.0.0.1:15353"}, .zones = .{} }'';
  changedFixture = ''.{ .listen = .{"127.0.0.1:15354"}, .zones = .{} }'';
  evaluate =
    settings:
    if isLinux then
      (inputs.nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          self.nixosModules.default
          {
            system.stateVersion = "26.05";
            services.z53 = settings;
          }
        ];
      }).config
    else
      (inputs.nix-darwin.lib.darwinSystem {
        inherit system;
        modules = [
          self.darwinModules.default
          {
            system.stateVersion = 6;
            services.z53 = settings;
          }
        ];
      }).config;
  enabled = evaluate {
    enable = true;
    config = fixture;
  };
  changed = evaluate {
    enable = true;
    config = changedFixture;
  };
  disabled = evaluate { };
  overridePackage = pkgs.writeShellScriptBin "z53" "exit 0";
  overridden = evaluate {
    enable = true;
    config = fixture;
    package = overridePackage;
  };
  missing = evaluate { enable = true; };
  configSource = enabled.environment.etc."z53/z53.zon".source;
  defaultPackage = self.packages.${system}.z53;
  require = name: condition: lib.assertMsg condition "z53 module assertion failed: ${name}";
  common = [
    (require "generated config text" (configSource.text == fixture))
    (require "required config" (
      !(builtins.tryEval missing.environment.etc."z53/z53.zon".source).success
    ))
    (require "disabled config absent" (!(disabled.environment.etc ? "z53/z53.zon")))
    (require "default package" (enabled.services.z53.package == defaultPackage))
  ];
  linuxTests =
    let
      unit = enabled.systemd.services.z53;
      flags = unit.serviceConfig;
    in
    [
      (require "dynamic user" flags.DynamicUser)
      (require "ambient capability" (flags.AmbientCapabilities == [ "CAP_NET_BIND_SERVICE" ]))
      (require "bounding set" (flags.CapabilityBoundingSet == flags.AmbientCapabilities))
      (require "failure restart" (flags.Restart == "on-failure"))
      (require "descriptor limit" (flags.LimitNOFILE == 1048576))
      (require "command" (flags.ExecStart == "${lib.getExe defaultPackage} -c /etc/z53/z53.zon"))
      (require "boot target" (unit.wantedBy == [ "multi-user.target" ]))
      (require "config restart trigger" (unit.restartTriggers == [ configSource ]))
      (require "config change restarts" (
        unit.restartTriggers != changed.systemd.services.z53.restartTriggers
      ))
      (require "disabled unit absent" (!(disabled.systemd.services ? z53)))
      (require "package override" (
        overridden.systemd.services.z53.serviceConfig.ExecStart
        == "${lib.getExe overridePackage} -c /etc/z53/z53.zon"
      ))
      (require "journald policy unchanged" (
        enabled.services.journald.settings == disabled.services.journald.settings
      ))
      (require "rendered unit" (lib.hasInfix "DynamicUser=true" enabled.systemd.units."z53.service".text))
    ];
  darwinTests =
    let
      flags = enabled.launchd.daemons.z53.serviceConfig;
      rotation = enabled.launchd.daemons.z53-logrotate.serviceConfig;
      rotationConfig = enabled.environment.etc."z53/logrotate.conf".source;
      plist = enabled.environment.launchDaemons."org.nixos.z53.plist".text;
    in
    [
      (require "root daemon" (flags.UserName == "root"))
      (require "run at load" flags.RunAtLoad)
      (require "keep alive" flags.KeepAlive)
      (require "command" (
        flags.ProgramArguments == [
          "${lib.getExe defaultPackage}"
          "-c"
          "/etc/z53/z53.zon"
        ]
      ))
      (require "stdout" (flags.StandardOutPath == "/var/log/z53.log"))
      (require "stderr" (flags.StandardErrorPath == "/var/log/z53.log"))
      (require "config identity" (flags.EnvironmentVariables.Z53_CONFIG_SOURCE == toString configSource))
      (require "config change reloads plist" (
        plist != changed.environment.launchDaemons."org.nixos.z53.plist".text
      ))
      (require "disabled daemon absent" (!(disabled.launchd.daemons ? z53)))
      (require "disabled rotation absent" (!(disabled.launchd.daemons ? z53-logrotate)))
      (require "package override" (
        builtins.head overridden.launchd.daemons.z53.serviceConfig.ProgramArguments
        == lib.getExe overridePackage
      ))
      (require "hourly rotation" (rotation.StartInterval == 3600))
      (require "rotation root" (rotation.UserName == "root"))
      (require "rotation state" (
        builtins.elemAt rotation.ProgramArguments 2 == "/var/log/z53-logrotate.status"
      ))
      (require "retention and descriptor preservation" (
        lib.hasInfix "copytruncate" rotationConfig.text
        && lib.hasInfix "rotate 7" rotationConfig.text
        && lib.hasInfix "maxsize 10M" rotationConfig.text
      ))
    ];
in
assert builtins.all (value: value) (common ++ (if isLinux then linuxTests else darwinTests));
pkgs.runCommand "z53-module-checks" { } ''
  echo '${system}: module assertions passed' > "$out"
''
