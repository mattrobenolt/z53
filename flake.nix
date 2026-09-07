{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    nix-darwin = {
      url = "github:nix-darwin/nix-darwin";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    mattware = {
      url = "github:mattrobenolt/nixpkgs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      flake-parts,
      nixpkgs,
      mattware,
      self,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      flake = {
        nixosModules.default = import ./nix/modules/nixos.nix { inherit self; };
        darwinModules.default = import ./nix/modules/darwin.nix { inherit self; };
      };

      perSystem =
        { system, ... }:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ mattware.overlays.default ];
          };
          build = import ./nix/package.nix { inherit pkgs; };
        in
        {
          packages.z53 = build.package;
          packages.default = build.package;
          formatter = pkgs.nixfmt;
          checks = {
            package = build.package;
            portable = build.portable;
            modules = import ./nix/tests/modules.nix { inherit inputs self pkgs; };
            style = import ./nix/tests/style.nix { inherit pkgs; };
          };
          devShells.default = pkgs.mkShell {
            packages =
              with pkgs;
              [
                zig_0_16
                zls_0_16
                ziglint
                zigdoc
                openssl
                pkg-config
                just
                dig
                nixfmt
                # #1: the native CI watchdog and its local checks use pinned tools.
                python3
                unixtools.ps
                actionlint
                llvmPackages.bintools
              ]
              ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.perf ]
              ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.logrotate ];
          };
        };
    };
}
