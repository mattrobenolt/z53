# SPEC §8.1 and §9.5: sandbox builds fetch only the manifest-pinned dependencies (#1).
{ pkgs }:
let
  inherit (pkgs) lib;
  source = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../build.zig
      ../build.zig.zon
      ../src
      ../tests
      ../scripts/fuzz.sh
      ../examples/launchpad.zon
      ../examples/darwin.zon
    ];
  };
  dependencies = pkgs.stdenvNoCC.mkDerivation {
    name = "z53-zig-dependencies";
    src = source;
    nativeBuildInputs = [
      pkgs.zig_0_16
      pkgs.git
      pkgs.cacert
    ];
    dontConfigure = true;
    dontFixup = true;
    buildPhase = ''
      export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-cache"
      export HOME="$TMPDIR"
      zig build --fetch=all
    '';
    installPhase = ''
      cp -r "$ZIG_GLOBAL_CACHE_DIR/p" "$out"
    '';
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    outputHash = "sha256-KYlOz/BScwrgf58y6uugfY9stkdBIXmulIn7RK0YODk=";
  };
  package = pkgs.stdenv.mkDerivation {
    pname = "z53";
    version = "0.0.0";
    src = source;
    strictDeps = true;
    nativeBuildInputs = [
      pkgs.zig_0_16.hook
      pkgs.pkg-config
    ];
    buildInputs = [ pkgs.openssl ];
    dontSetZigDefaultFlags = true;
    zigBuildFlags = [
      "-Doptimize=ReleaseSafe"
      "-Dcpu=baseline"
      "--system"
      "zig-pkg"
    ];
    postConfigure = ''
      mkdir zig-pkg
      archives=(${dependencies}/*.tar.gz)
      test "''${#archives[@]}" -eq 6
      for archive in "''${archives[@]}"; do
        tar -xzf "$archive" -C zig-pkg
      done
    '';
    doInstallCheck = true;
    nativeInstallCheckInputs = [ pkgs.llvmPackages.bintools ];
    installCheckPhase = ''
      runHook preInstallCheck
      test "$(find "$out" -type f)" = "$out/bin/z53"
      status=0
      env -u LD_LIBRARY_PATH -u DYLD_LIBRARY_PATH "$out/bin/z53" -c >stdout 2>stderr || status=$?
      test "$status" -eq 1
      test ! -s stdout
      printf 'z53: usage: z53 [-c path]\n' >expected
      cmp expected stderr
      ${
        if pkgs.stdenv.hostPlatform.isLinux then
          ''
            llvm-readelf -d "$out/bin/z53" >linkage
            grep -F 'libcrypto.so.3' linkage
            grep -F '${lib.getLib pkgs.openssl}/lib' linkage
          ''
        else
          ''
            llvm-objdump --macho --dylibs-used "$out/bin/z53" >linkage
            grep -F '${lib.getLib pkgs.openssl}/lib/libcrypto' linkage
          ''
      }
      runHook postInstallCheck
    '';
    meta = {
      description = "Bounded DNS caching forwarder";
      homepage = "https://github.com/mattrobenolt/z53";
      license = lib.licenses.asl20;
      mainProgram = "z53";
      platforms = [
        "aarch64-linux"
        "x86_64-linux"
        "aarch64-darwin"
      ];
    };
  };
in
{
  inherit package;
  portable = package.overrideAttrs {
    pname = "z53-portable-checks";
    nativeBuildInputs = [
      pkgs.zig_0_16.hook
      pkgs.pkg-config
      pkgs.python3
      pkgs.unixtools.ps
    ];
    doCheck = true;
    postPatch = ''
      substituteInPlace tests/fuzz-gate.sh \
        --replace-fail '#!/usr/bin/env bash' '#!${pkgs.bash}/bin/bash'
      patchShebangs scripts/fuzz.sh
    '';
    # The full runtime/restart suite remains a separate native acceptance gate.
    checkPhase = ''
      runHook preCheck
      command -v ps
      set -o pipefail
      zig build -j2 -Doptimize=ReleaseSafe -Dcpu=baseline --system zig-pkg -Dunit-filter=TLS test-unit 2>&1 | tee foundation.log
      # ztest succeeds on an empty selection, so pin the promised TLS coverage.
      grep -Fx 'ztest: Running 3 tests...' foundation.log
      zig build -j2 -Doptimize=ReleaseSafe -Dcpu=baseline --system zig-pkg test-config test-resolver test-wire test-containers bench-smoke
      runHook postCheck
    '';
  };
}
