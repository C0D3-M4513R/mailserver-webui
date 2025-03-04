{
  inputs = {
    naersk.url = "github:nmattia/naersk/master";
    # This must be the stable nixpkgs if you're running the app on a
    # stable NixOS install.  Mixing EGL library versions doesn't work.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-compat = {
      url = github:edolstra/flake-compat;
      flake = true;
    };
  };

  outputs = { self, nixpkgs, utils, naersk, rust-overlay, ... }:
    utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfree = true;
        };
        naersk-lib = pkgs.callPackage naersk {
            cargo = pkgs.rust-bin.stable.latest.default;
            rustc = pkgs.rust-bin.stable.latest.default;
        };
        manifest = (builtins.fromTOML (builtins.readFile ./modern_mzident/Cargo.toml)).package;
      in
      {
        defaultPackage = naersk-lib.buildPackage {
          src = pkgs.lib.cleanSource ./.;
          doCheck = true;
          pname = manifest.name;
          nativeBuildInputs = [
            pkgs.autoPatchelfHook
          ];
          buildInputs = with pkgs; [
            pkgs.rust-bin.stable.latest.default
          ];
        };

        defaultApp = utils.lib.mkApp {
          drv = self.defaultPackage."${system}";
        };

        devShell = with pkgs; mkShell {
          buildInputs = [
            #cargo
            cargo-insta
            pre-commit
            samply    #for cpu  profiling
            heaptrack #for heap analysis
            sqlite-interactive #for sqlite db diff's
            #rust-analyzer
            #rustPackages.clippy
            #rustc
            #rustfmt
            tokei
            sqlx-cli
  (vscode-with-extensions.override {
    vscodeExtensions = with vscode-extensions; [
      bbenoist.nix
      rust-lang.rust-analyzer
      vadimcn.vscode-lldb
      #ms-azuretools.vscode-docker
      #ms-vscode-remote.remote-ssh
    ];
  })

          ];
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
          GIT_EXTERNAL_DIFF = "${difftastic}/bin/difft";
          DATABASE_URL = "sqlite://db.sqlite";
          RUST_BACKTRACE= "1";
          RUST_LIB_BACKTRACE = "1";
        };
      });
}
