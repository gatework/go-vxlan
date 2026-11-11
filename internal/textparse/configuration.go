// Package textparse provides the shared configuration text matching boundary.
package textparse

import (
	"regexp"
)

// Match returns the capture groups of the first matching expression.
func Match(pattern, s string) []string {
	return regexp.MustCompile("^(?:" + pattern + ")$").FindStringSubmatch(s)
}
