package main

import (
	"testing"
	"time"
)

// A name that cannot be a file name is refused, so the common name in a
// certificate always matches its path on disk.
func TestNameThatCannotBeAFileNameIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"../evil", "a/b", `a\b`, ".", ".."} {
		if err := run(config{out: dir, clients: name, ttl: time.Hour, caTTL: 24 * time.Hour}); err == nil {
			t.Errorf("accepted name %q", name)
		}
	}
}
