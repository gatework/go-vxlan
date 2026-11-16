package nxos

import textparser "github.com/gatework/parser"

// newTextContent shares byte-exact indexing between configuration and runtime.
func newTextContent(text string) (*textparser.Content, error) {
	// The public string API already owns its entire input and historically imposed
	// no size cap. Bound indexing by that known size instead of silently applying
	// the shared parser's smaller default limits to previously accepted output.
	return textparser.New(text, textparser.Limits{
		MaxBytes: max(len(text), textparser.DefaultMaxBytes),
		MaxLines: max(len(text), textparser.DefaultMaxLines),
	})
}
