# isudo for NixOS. The store cannot hold a setuid file, so `isudo` here is
# not setuid: nix/module.nix makes the setuid copy with security.wrappers,
# and the paths below point the other programs at it.
{ lib, rustPlatform, src
, setuidPath ? "/run/wrappers/bin/isudo"
, securePath ? "/run/wrappers/bin:/run/current-system/sw/bin"
}:

rustPlatform.buildRustPackage {
  pname = "isudo";
  version = "0.1.0";
  inherit src;
  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [ "-p" "isudo" "-p" "isudo-helper" "-p" "isudo-admin" "-p" "isudo-relay" ];

  env = {
    ISUDO_LIBEXEC_DIR = "${placeholder "out"}/libexec";
    ISUDO_SETUID_PATH = setuidPath;
    ISUDO_DEFAULT_SECURE_PATH = securePath;
  };

  # The suite (nextest, the simulator, the setuid container test) runs in CI.
  doCheck = false;

  postInstall = ''
    mkdir -p $out/libexec
    mv $out/bin/isudo-helper $out/libexec/isudo-helper
  '';

  meta = {
    description = "sudo with approval from your phone";
    homepage = "https://github.com/burke/isudo";
    license = lib.licenses.mit;
    mainProgram = "isudo";
    platforms = lib.platforms.linux;
  };
}
