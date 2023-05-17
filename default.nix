{ stdenv
, cmake
, cli11
, openssl
, fmt
}:

stdenv.mkDerivation rec {
  name = "https_client";

  srcs = [ ./CMakeLists.txt ./main.cpp ];
  unpackPhase = ''
    for srcFile in $srcs; do
      cp $srcFile $(stripHash $srcFile)
    done
  '';

  nativeBuildInputs = [ cmake ];
  buildInputs = [ openssl cli11 fmt ];
}
