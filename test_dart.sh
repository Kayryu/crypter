#!/bin/bash

# if windows 
cargo build

cp ./target/debug/signer_ffi.dll ./examples/ffi/dart/

cd ./examples/ffi/dart
dart ./bin/main.dart