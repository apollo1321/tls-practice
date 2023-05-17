{
  description = "simple https client";

  outputs = { self, nixpkgs, flake-utils } @args: flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
        inherit system;
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
