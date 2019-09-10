{ nixpkgs ? <nixpkgs> }:
let
  pkgs = import nixpkgs {};
  naersk = pkgs.callPackage (pkgs.fetchFromGitHub {
    owner = "nmattia";
    repo = "naersk";
    rev = "5b148cf5ef11aa80a035a27f08b611eff5305647";
    sha256 = "1mfyyk3glhz4kjmvsi2srsmxzn4d2l64k1bavc7lzp3lq01gv599";
  }) {};
in (naersk.buildPackage (pkgs.lib.cleanSource ./.) { doDoc = false; doCheck = false; })
