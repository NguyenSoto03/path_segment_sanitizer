// Package path_segment_sanitizer cleans untrusted input into safe path segments.
package path_segment_sanitizer

import (
	"strings"
	"unicode"
)

// Sanitize converts an untrusted string into a single safe path segment.
//
// It removes path separators, null bytes, and traversal sequences. The result
// never contains '/', '\\', the NUL byte, or a '.'/'..' component. It does not
// guarantee uniqueness or non-emptiness; callers that require a non-empty name
// should supply a fallback.
//
// The policy is deliberately conservative: any character that could be
// interpreted as a separator or control character is dropped rather than
// escaped, because downstream filesystems disagree about escaping rules.
func Sanitize(input string) string {
	// Remove NUL and ASCII control characters first. They can terminate strings
	// in C APIs and are never valid in a path segment on common filesystems.
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if r == 0 || r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	s := b.String()

	// Normalize both POSIX and Windows separators to '/' so the split below is
	// uniform, then split and drop empty and traversal components.
	s = strings.ReplaceAll(s, "\\", "/")

	parts := strings.Split(s, "/")
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			continue
		}
		kept = append(kept, part)
	}

	// Join with '_' rather than '/' so the result is a single segment. This
	// preserves information from multi-component inputs instead of silently
	// discarding everything after the first separator.
	result := strings.Join(kept, "_")

	// The join above can produce a leading or trailing underscore when the
	// original had leading/trailing separators. Trim those to keep the result
	// tidy; internal underscores are meaningful.
	result = strings.Trim(result, "_")

	// A segment consisting only of dots is still dangerous on some systems
	// (e.g. "..." can be treated as a parent on Windows). Collapse any run of
	// dots to a single dot so "..." becomes ".", which is harmless as a name
	// but we drop it entirely if it is the whole segment.
	if isAllDots(result) {
		return ""
	}

	return result
}

// isAllDots reports whether s is non-empty and consists solely of '.' runes.
func isAllDots(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '.' {
			return false
		}
	}
	return true
}

// IsSafe reports whether s is already a safe single path segment according to
// the same policy used by Sanitize. It is provided so callers can validate
// without allocating a replacement.
func IsSafe(s string) bool {
	if s == "" {
		return false
	}
	if s == "." || s == ".." {
		return false
	}
	if isAllDots(s) {
		return false
	}
	for _, r := range s {
		if r == 0 || r < 0x20 || r == 0x7f {
			return false
		}
		if r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

// SanitizeWithFallback returns Sanitize(input), or fallback if the sanitized
// result is empty. It is a convenience for callers that need a usable name.
func SanitizeWithFallback(input, fallback string) string {
	out := Sanitize(input)
	if out == "" {
		return fallback
	}
	return out
}

// ReplaceUnsafe replaces every rune that is not a letter, digit, '-', '_', or
// '.' with replacement. It is a stricter alternative to Sanitize for callers
// that want to preserve a single segment's shape rather than join components.
func ReplaceUnsafe(input string, replacement rune) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if isAllowedRune(r) {
			b.WriteRune(r)
		} else {
			b.WriteRune(replacement)
		}
	}
	return b.String()
}

// isAllowedRune reports whether r is permitted in a path segment by
// ReplaceUnsafe. Letters and digits are allowed, as are '-', '_', and '.'.
// Everything else, including separators and controls, is replaced.
func isAllowedRune(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return true
	}
	switch r {
	case '-', '_', '.':
		return true
	default:
		return false
	}
}
