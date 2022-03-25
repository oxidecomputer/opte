# OPTE Package

This binary can be used to produce an Omicron-branded Zone image, which consists
of the OPTE kernel module and associated command line applications in a
specially-formatted tarball.

A manifest describing this Zone image exists in
[package-manifest.toml](package-manifest.toml), and the resulting image is
created as `out/opte.tar.gz`.

To create the Zone image first build a release versions of [opteadm](../opteadm)
and [xde](../xde). Then run this binary.

```rust
$ cargo run
```
