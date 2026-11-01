#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <moonbit.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

MOONBIT_FFI_EXPORT int32_t cedar_read(const unsigned char *path, unsigned char *out) {
  int n = Moonbit_array_length(path);
  if (memchr(path, 0, (size_t)n)) return -1;
  char *name = malloc((size_t)n + 1);
  if (!name) return -1;
  memcpy(name, path, (size_t)n); name[n] = 0;
  FILE *f = NULL;
#ifdef _WIN32
  int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name, -1, NULL, 0);
  if (count) {
    wchar_t *wide = malloc((size_t)count * sizeof(wchar_t));
    if (wide) {
      if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name, -1, wide, count)) f = _wfopen(wide, L"rb");
      free(wide);
    }
  }
#else
  int fd = open(name, O_RDONLY | O_NONBLOCK);
  if (fd >= 0) { f = fdopen(fd, "rb"); if (!f) close(fd); }
#endif
  free(name);
  if (!f) return -1;
#ifdef _WIN32
  struct _stat64 info;
  if (_fstat64(_fileno(f), &info) != 0 || (info.st_mode & _S_IFMT) != _S_IFREG) { fclose(f); return -1; }
#else
  struct stat info;
  if (fstat(fileno(f), &info) != 0 || !S_ISREG(info.st_mode)) { fclose(f); return -1; }
#endif
  size_t size = fread(out, 1, (size_t)Moonbit_array_length(out), f);
  int failed = ferror(f);
  fclose(f);
  return failed ? -1 : (int32_t)size;
}

MOONBIT_FFI_EXPORT void cedar_exit(int32_t code) { exit(code); }
MOONBIT_FFI_EXPORT void cedar_stderr(const unsigned char *s) {
  fwrite(s, 1, (size_t)Moonbit_array_length(s), stderr);
  fputc('\n', stderr);
}
