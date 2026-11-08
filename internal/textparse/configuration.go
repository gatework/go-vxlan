package textparse

import (
	"regexp"
)

func Match(pattern, s string) []string {
	return regexp.MustCompile("^(?:" + pattern + ")$").FindStringSubmatch(s)
}
