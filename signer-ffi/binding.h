#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

int64_t add(int64_t a, int64_t b);

void rust_cstr_free(char *s);

char *rust_greeting(const char *to);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
