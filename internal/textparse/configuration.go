// Package textparse provides the shared configuration text matching boundary.
package textparse

import (
	"regexp"
	"sync"
)

// Patterns are internal grammar constants, never device-supplied text.
// Reuse the anchored expression across lines and concurrent parsers.
var patterns sync.Map

// Match returns capture groups from the anchored expression.
func Match(pattern, s string) []string {
	if re, ok := patterns.Load(pattern); ok {
		return compiledPattern(re).FindStringSubmatch(s)
	}
	re := regexp.MustCompile("^(?:" + pattern + ")$")
	value, _ := patterns.LoadOrStore(pattern, re)
	return compiledPattern(value).FindStringSubmatch(s)
}

func compiledPattern(value any) *regexp.Regexp {
	re, ok := value.(*regexp.Regexp)
	if !ok {
		panic("textparse: invalid internal regexp")
	}
	return re
}
