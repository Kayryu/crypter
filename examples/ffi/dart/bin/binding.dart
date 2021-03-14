/// bindings for `libsigner`

import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart' as ffi;

// ignore_for_file: unused_import, camel_case_types, non_constant_identifier_names
final DynamicLibrary _dl = _open();
/// Reference to the Dynamic Library, it should be only used for low-level access
final DynamicLibrary dl = _dl;
DynamicLibrary _open() {
  if (Platform.isWindows) return DynamicLibrary.open('signer_ffi.dll');
  if (Platform.isAndroid) return DynamicLibrary.open('libsigner_ffi.so');
  if (Platform.isIOS) return DynamicLibrary.executable();
  throw UnsupportedError('This platform is not supported.');
}

/// C function `add`.
int add(
  int a,
  int b,
) {
  return _add(a, b);
}
final _add_Dart _add = _dl.lookupFunction<_add_C, _add_Dart>('add');
typedef _add_C = Int64 Function(
  Int64 a,
  Int64 b,
);
typedef _add_Dart = int Function(
  int a,
  int b,
);

/// C function `rust_cstr_free`.
void rust_cstr_free(
  Pointer<ffi.Utf8> s,
) {
  _rust_cstr_free(s);
}
final _rust_cstr_free_Dart _rust_cstr_free = _dl.lookupFunction<_rust_cstr_free_C, _rust_cstr_free_Dart>('rust_cstr_free');
typedef _rust_cstr_free_C = Void Function(
  Pointer<ffi.Utf8> s,
);
typedef _rust_cstr_free_Dart = void Function(
  Pointer<ffi.Utf8> s,
);

/// C function `rust_greeting`.
Pointer<ffi.Utf8> rust_greeting(
  Pointer<ffi.Utf8> to,
) {
  return _rust_greeting(to);
}
final _rust_greeting_Dart _rust_greeting = _dl.lookupFunction<_rust_greeting_C, _rust_greeting_Dart>('rust_greeting');
typedef _rust_greeting_C = Pointer<ffi.Utf8> Function(
  Pointer<ffi.Utf8> to,
);
typedef _rust_greeting_Dart = Pointer<ffi.Utf8> Function(
  Pointer<ffi.Utf8> to,
);

/// Binding to `allo-isolate` crate
void store_dart_post_cobject(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
) {
  _store_dart_post_cobject(ptr);
}
final _store_dart_post_cobject_Dart _store_dart_post_cobject = _dl.lookupFunction<_store_dart_post_cobject_C, _store_dart_post_cobject_Dart>('store_dart_post_cobject');
typedef _store_dart_post_cobject_C = Void Function(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
);
typedef _store_dart_post_cobject_Dart = void Function(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
);
