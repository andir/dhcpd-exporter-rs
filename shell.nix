with import <nixpkgs> {};
mkShell {
  buildInputs = [ cargo rustc rustPackages.clippy linuxPackages.perf ];
}
