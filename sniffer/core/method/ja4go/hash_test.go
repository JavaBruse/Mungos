package ja4go

import "testing"

func TestHash12(t *testing.T) {
	if got, want := Hash12("551d0f,551d25,551d11"), "aae71e8db6d7"; got != want {
		t.Fatalf("Hash12 mismatch: got %q, want %q", got, want)
	}
	if got, want := Hash12(""), "000000000000"; got != want {
		t.Fatalf("Hash12(\"\") mismatch: got %q, want %q", got, want)
	}
}

