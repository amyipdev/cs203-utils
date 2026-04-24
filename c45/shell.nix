{ pkgs ? import <nixpkgs> {} }:

let
  python = pkgs.python313;

  pythonEnv = python.withPackages (ps: with ps; [
    numpy
    pandas
    matplotlib
    scikit-learn
    jupyter
    ipykernel
  ]);
in
pkgs.mkShell {
  buildInputs = [
    pythonEnv
  ];
}
