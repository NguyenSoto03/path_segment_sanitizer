package path_segment_sanitizer

import "testing"

func TestSanitizeRemovesSeparators(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"posix separator", "a/b", "a_b"},
		{"windows separator", `a\b`, "a_b"},
		{"mixed separators", `a/b\c`, "a_b_c"},
		{"leading separator", "/etc/passwd", "etc_passwd"},
		{"trailing separator", "dir/", "dir"},
		{"double separator", "a//b", "a_b"},
		{"only separators", "///", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Sanitize(tc.input)
			if got != tc.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSanitizeRemovesTraversal(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"simple parent", "..", ""},
		{"parent with child", "../etc", "etc"},
		{"child with parent", "a/../b", "a_b"},
		{"deep traversal", "../../../../etc/passwd", "etc_passwd"},
		{"current dir", ".", ""},
		{"current dir with child", "./a", "a"},
		{"three dots", "...", ""},
		{"four dots", "....", ""},
		{"dot dot mixed", "a..b", "a..b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Sanitize(tc.input)
			if got != tc.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSanitizeRemovesNullBytesAndControls(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"null byte", "a\x00b", "ab"},
		{"newline", "a\nb", "ab"},
		{"tab", "a\tb", "ab"},
		{"carriage return", "a\rb", "ab"},
		{"delete", "a\x7fb", "ab"},
		{"null only", "\x00", ""},
		{"control with separator", "a\x00/b", "a_b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Sanitize(tc.input)
			if got != tc.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSanitizeKeepsOrdinaryText(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"hello-world", "hello-world"},
		{"hello_world", "hello_world"},
		{"file.txt", "file.txt"},
		{"UPPER", "UPPER"},
		{"123", "123"},
		{"café", "café"},
		{"日本語", "日本語"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := Sanitize(tc.input)
			if got != tc.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSanitizeEmptyInput(t *testing.T) {
	if got := Sanitize(""); got != "" {
		t.Fatalf("Sanitize(\"\") = %q, want empty", got)
	}
}

func TestIsSafe(t *testing.T) {
	safe := []string{"a", "a-b", "a_b", "file.txt", "café"}
	for _, s := range safe {
		if !IsSafe(s) {
			t.Errorf("IsSafe(%q) = false, want true", s)
		}
	}
	unsafe := []string{"", ".", "..", "...", "a/b", `a\b`, "a\x00b", "a\nb"}
	for _, s := range unsafe {
		if IsSafe(s) {
			t.Errorf("IsSafe(%q) = true, want false", s)
		}
	}
}

func TestSanitizeWithFallback(t *testing.T) {
	if got := SanitizeWithFallback("../etc", "fallback"); got != "etc" {
		t.Fatalf("SanitizeWithFallback(\"../etc\") = %q, want %q", got, "etc")
	}
	if got := SanitizeWithFallback("..", "fallback"); got != "fallback" {
		t.Fatalf("SanitizeWithFallback(\"..\") = %q, want %q", got, "fallback")
	}
	if got := SanitizeWithFallback("", "fallback"); got != "fallback" {
		t.Fatalf("SanitizeWithFallback(\"\") = %q, want %q", got, "fallback")
	}
	if got := SanitizeWithFallback("good", "fallback"); got != "good" {
		t.Fatalf("SanitizeWithFallback(\"good\") = %q, want %q", got, "good")
	}
}

func TestReplaceUnsafe(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"separator", "a/b", "a_b"},
		{"space", "a b", "a_b"},
		{"null", "a\x00b", "a_b"},
		{"allowed", "a-b_c.d", "a-b_c.d"},
		{"multiple", "a b/c", "a_b_c"},
		{"unicode letter", "café", "café"},
		{"unicode symbol", "a€b", "a_b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ReplaceUnsafe(tc.input, '_')
			if got != tc.want {
				t.Fatalf("ReplaceUnsafe(%q, '_') = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestReplaceUnsafeCustomReplacement(t *testing.T) {
	got := ReplaceUnsafe("a b", '-')
	if got != "a-b" {
		t.Fatalf("ReplaceUnsafe(\"a b\", '-') = %q, want %q", got, "a-b")
	}
}
