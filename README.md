# Paillier

Efficient pure-Rust library for the [Paillier](https://en.wikipedia.org/wiki/Paillier_cryptosystem) partially homomorphic encryption scheme, offering both plain and packed variants.

**Important**: while we have followed recommendations regarding the scheme itself, so far no particular efforts have been made to harden the library against non-cryptographic attacks, including side-channel attacks.


# Installation

Note that some functionality such as **key generation** is *not* included by default. See the [Building](#Building) section for more details.

## GitHub
```bash
git clone https://github.com/snipsco/rust-paillier
cd rust-paillier
cargo build --release
```


# Building

## Key generation

Key generation is optional since it is not always needed yet adds several extra (heavy) dependencies. To include use
```
cargo build --features "keygen"
```

## Arithmetic

The library supports the use of different arithmetic libraries, currently defaulting to [`ramp`](https://github.com/Aatch/ramp) for efficiency.

For [`ramp`](https://github.com/Aatch/ramp)-only compilation use `cargo build` or
```
cargo build --features "useramp"
```
for [`num`](https://github.com/rust-num/num)-only compilation use
```
cargo build --no-default-features --features "usenum"
```
and finally, use
```
cargo build --features "useramp usenum"
```
to have both available (useful for e.g. performance tests).


# Performance
These numbers were obtained by running
```
cargo bench
```
using the nightly toolchain.

# License

Licensed under either of
 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
 