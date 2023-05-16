{
  description = "simple https client";

  outputs = { self, nixpkgs, flake-utils } @args: flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
        inherit system;
        crossOverlays = [
          (final: prev:
            let
              pkgs = ((import nixpkgs) { inherit system; });
            in
            let
              llvmPackages_15_darwin = pkgs.callPackage (import (pkgs.path + "/pkgs/development/compilers/llvm/15")) ({
                inherit (pkgs.stdenvAdapters) overrideCC;
                buildLlvmTools = pkgs.buildPackages.llvmPackages_15.tools;
                targetLlvmLibraries = {
                  compiler-rt = pkgs.llvmPackages_15.compiler-rt.override { stdenv = pkgs.llvmPackages_15.stdenv; };
                  libcxx = pkgs.llvmPackages_15.libcxx;
                };
                targetLlvm = pkgs.targetPackages.llvmPackages_15.llvm or pkgs.llvmPackages_15.llvm;
              });
            in
            let
              llvmStdenv = with pkgs; overrideCC stdenv llvmPackages_15_darwin.tools.clang;
            in
            {
              /* stdenv = pkgs.llvmPackages_15.stdenv; */
              stdenv =
                llvmStdenv.override
                  (final:
                    { preHook = final.preHook + "export NIX_CFLAGS_COMPILE=-fsanitize=address\n"; }
                  );
              asio = prev.asio.overrideAttrs (final: prev: { propagatedBuildInputs = [ ]; });
            })
        ];
      };
    in
    rec {
      packages = rec {
        client = pkgs.callPackage ./default.nix { };
        default = client;
      };
      apps = rec {
        client = flake-utils.lib.mkApp { drv = self.packages.${system}.client; };
        default = client;
      };
      devShells.default = pkgs.mkShell rec {
        name = "https client dev environment";
        inputsFrom = [ packages.client ];
      };
    }
  );
}
