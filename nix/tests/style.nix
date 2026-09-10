# SPEC §9.5: both Zig lint entry points and both formatters are gates.
{ pkgs }:
let
  source = pkgs.lib.fileset.toSource {
    root = ../..;
    fileset = pkgs.lib.fileset.unions [
      ../../.ziglint.zon
      ../../build.zig
      ../../build.zig.zon
      ../../Justfile
      ../../src
      ../../tests
      ../../flake.nix
      ../../nix
    ];
  };
in
pkgs.runCommand "z53-style-checks"
  {
    nativeBuildInputs = [
      pkgs.zig_0_16
      pkgs.ziglint
      pkgs.nixfmt
      pkgs.just
    ];
  }
  ''
    cd ${source}
    just --fmt --check
    zig fmt --check build.zig build.zig.zon src tests
    ziglint
    ziglint build.zig src tests
    nixfmt --check flake.nix nix/*.nix nix/modules/*.nix nix/tests/*.nix
    touch "$out"
  ''
