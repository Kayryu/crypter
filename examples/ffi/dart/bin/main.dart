import 'binding.dart';
import 'package:ffi/ffi.dart' as ffi;

class Signer {
  /// Computes a greeting for the given name using the native function
  static String greet(String name) {
    final ptrName = ffi.Utf8.toUtf8(name);

    // Native call
    final ptrResult = rust_greeting(ptrName);

    // Cast the result pointer to a Dart string
    final result = ffi.Utf8.fromUtf8(ptrResult.cast<ffi.Utf8>());

    // Clone the given result, so that the original string can be freed
    final resultCopy = "" + result + "~~";

    // Free the native value
    _free(result);

    return resultCopy;
  }

  /// Releases the memory allocated to handle the given (result) value
  static void _free(String value) {
    final ptr = ffi.Utf8.toUtf8(value);
    return rust_cstr_free(ptr);
  }
}

void main(List<String> arguments) {
  print(add(1, 2));
  var echo = Signer.greet('kayryu');
  print(echo);
}
