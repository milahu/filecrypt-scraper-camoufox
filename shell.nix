{ pkgs ? import <nixpkgs> {} }:

with pkgs;

mkShell {
  buildInputs = [
    (python3.withPackages (pp: with pp; [
      nur.repos.milahu.python3.pkgs.camoufox
      cryptography
    ]))
  ];
  FIREFOX_ADDON_DARKREADER = nur.repos.milahu.python3.pkgs.camoufox.firefox-addons.darkreader;
}
