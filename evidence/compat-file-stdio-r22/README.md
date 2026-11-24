# POSIX stdio compatibility control

This run executes an unmodified C/POSIX fixture twice through Jasper:
`creat("/tmp/jasper-file-stdio")`, `fdopen(..., "w")`, `fputs`, `fclose`.

Both runs print `FILE_STDIO_OK`, exit zero with `syscalls=38`, and recover
resources before Wine starts. Wine subsequently reaches the same
`free(): invalid pointer` failure, which isolates the remaining heap corruption
from the generic stdio operation itself.
