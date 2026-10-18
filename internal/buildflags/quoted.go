package buildflags

import (
	"fmt"
	"strings"
)

// Fields follows the Go command's quoted argument grammar. A leading quote
// delimits one whole field with literal contents; interior quotes are ordinary
// bytes. This is neither shell expansion nor the tool response-file grammar.
func Fields(text string) ([]string, error) {
	var fields []string
	for {
		text = strings.TrimLeft(text, " \t\r\n")
		if text == "" {
			return fields, nil
		}
		if quote := text[0]; quote == '\'' || quote == '"' {
			end := strings.IndexByte(text[1:], quote)
			if end < 0 {
				return nil, fmt.Errorf("unterminated %c field", quote)
			}
			fields = append(fields, text[1:1+end])
			text = text[2+end:]
		} else {
			end := strings.IndexAny(text, " \t\r\n")
			if end < 0 {
				return append(fields, text), nil
			}
			fields = append(fields, text[:end])
			text = text[end:]
		}
	}
}

// Join encodes whole arguments for Fields, which treats quoted contents
// literally and has no escape syntax. A word needing quotes that contains both
// quote characters cannot be represented and is refused. NUL cannot be passed
// to a process and is refused as well.
func Join(fields []string) (string, error) {
	encoded := make([]string, len(fields))
	for i, field := range fields {
		if strings.IndexByte(field, 0) >= 0 {
			return "", fmt.Errorf("argument %d contains NUL", i)
		}
		switch {
		case field != "" && field[0] != '\'' && field[0] != '"' && !strings.ContainsAny(field, " \t\r\n"):
			encoded[i] = field
		case !strings.ContainsRune(field, '\''):
			encoded[i] = "'" + field + "'"
		case !strings.ContainsRune(field, '"'):
			encoded[i] = `"` + field + `"`
		default:
			return "", fmt.Errorf("argument %d cannot be represented by Go whole-word quoting", i)
		}
	}
	return strings.Join(encoded, " "), nil
}
