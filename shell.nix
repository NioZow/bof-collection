with import <nixpkgs> {
  crossSystem = {
    config = "x86_64-w64-mingw32";
  };
};

mkShell {
  buildInputs = [ zlib ];
}
