{
  description = "isudo: sudo with approval from your phone";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      # mkShellNoCC on purpose: the setuid binary must link against the system
      # libraries with the system linker, not against dylibs in the Nix store.
      devShells = forAll (pkgs: {
        default = pkgs.mkShellNoCC {
          packages = with pkgs; [ cargo rustc clippy rustfmt rust-analyzer cargo-nextest proverif xcodegen ];
        };
      });
    };
}
