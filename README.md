# path_segment_sanitizer

Cleans untrusted user input into safe path segments by removing separators, null bytes, and traversal sequences.

```go
package main

import (
	"fmt"

	ps "path_segment_sanitizer"
)

func main() {
	fmt.Println(ps.Sanitize("../../etc/passwd")) // etc_passwd
	fmt.Println(ps.Sanitize("a/b\\c"))            // a_b_c
	fmt.Println(ps.Sanitize("a\x00b"))            // ab
	fmt.Println(ps.IsSafe(".."))                  // false
	fmt.Println(ps.SanitizeWithFallback("..", "unnamed")) // unnamed
	fmt.Println(ps.ReplaceUnsafe("a b/c", '_'))   // a_b_c
}
```

## Why this exists

Applications that accept a filename or path component from a user must not pass it
to the filesystem unchanged. A value like `../../etc/passwd` or `a\x00b` can escape
the intended directory or truncate a string in a C API. This library reduces such
input to a single segment by dropping control characters, normalising both POSIX
and Windows separators, and discarding `.` and `..` components.

The trade-off is lossy: rather than escaping separators, it removes them and joins
the remaining components with `_`. Escaping would require agreement on an escape
scheme with every downstream filesystem, which is not portable. Removing is
predictable and safe; if you need the original structure you should not be using
an untrusted string as a path in the first place.

## API

- `Sanitize(input string) string` — returns a safe single segment, or `""` if nothing safe remains.
- `IsSafe(s string) bool` — reports whether `s` is already safe under the same policy.
- `SanitizeWithFallback(input, fallback string) string` — returns `Sanitize(input)`, or `fallback` when that is empty.
- `ReplaceUnsafe(input string, replacement rune) string` — replaces every character that is not a letter, digit, `-`, `_`, or `.` with `replacement`.

## The awkward edge

A segment consisting only of dots (`"..."`, `"...."`) is dropped entirely, because
some Windows APIs treat runs of dots as parent references. If you need a name for
such input, use `SanitizeWithFallback`. Also note that `Sanitize` does not guarantee
a unique or non-empty result; it only guarantees that the result contains no
separator, no control character, and no traversal component.
