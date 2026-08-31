package main

import (
	"fmt"
	"strings"
)

// splitNames parses a comma separated list, rejecting anything that cannot be
// used as a file name. Rejecting is deliberate: silently rewriting a name would
// make the common name in the certificate differ from the path on disk.
func splitNames(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var names []string
	seen := make(map[string]bool)
	for _, raw := range strings.Split(s, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
			return nil, fmt.Errorf("invalid name %q", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate name %q", name)
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}
