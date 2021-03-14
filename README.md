# crypter

A cross platform cryptograph library.

## Requires

- Rust
    * cbindgen;
    * dart-bindgen

- Dart
- Flutter

## Docs

- [flutter-rust-ffi](https://github.com/brickpop/flutter-rust-ffi/blob/master/README.md)

## Support crypto

## Support Platform



# Run dev

* Build lib.
```
cargo build
```

* Run dart

copy lib to /bin. then run.

- Windows

```
cp ./target/debug/signer_ffi.dll ./examples/ffi/dart/

cd ./examples/ffi/dart
dart ./bin/main.dart
```