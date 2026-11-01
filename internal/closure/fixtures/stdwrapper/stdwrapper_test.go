package stdwrapper

import (
	"html/template"
	"testing"
)

func BenchmarkTemplateParseFiles(b *testing.B) {
	for b.Loop() {
		_, _ = template.ParseFiles("fixture.tmpl")
	}
}
