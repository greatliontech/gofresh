package gofresh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/guard"
)

// fullFingerprint is a code-result fingerprint with every optional key
// present.
func fullFingerprint() Fingerprint {
	return Fingerprint{
		MaximalClosure:       "0123456789abcdef0123456789abcdef",
		TestVariantClosure:   "fedcba9876543210fedcba9876543210",
		ObservationAssertion: "caller assertion",
		ObservationProof: ObservationProof{
			Strategy:   ObservationRTA,
			Subject:    Subject{Package: "example.com/m/p", Symbol: "TestX"},
			Observable: false,
			Reason:     "reaches os.Getenv",
			Evidence:   "00112233445566778899aabbccddeeff",
		},
		Guards:                   guard.Guards{Toolchain: "go1.27.0 linux/amd64", BuildConfig: "b1"},
		PurityAssertion:          "source directive",
		DynamicStateVouches:      "example.com/m/p.state",
		SingleSubjectDischarges:  "example.com/m/p.single",
		PackageProcessDischarges: "example.com/m/p.proc",
		DynamicStateStrategy:     DynamicStateStrategy,
		ClosureStrategy:          ClosureStrategy,
		RuntimeInputs:            "manifest",
		RuntimeDigest:            "ffeeddccbbaa99887766554433221100",
		ResultKind:               CodeResult,
	}
}

// TestFingerprintRecordIsTheFleetForm pins the record form byte for
// byte in both directions: the seventeen keys in their order, the
// guards flattened, the proof nested with its package and symbol, every
// optional key omitted when empty — the bytes stipulator's witness
// store already holds inside its indented envelope, so its records
// decode, and their values re-encode to the same compact bytes
// (REQ-fresh-fingerprint-record).
func TestFingerprintRecordIsTheFleetForm(t *testing.T) {
	full := fullFingerprint()
	want := `{"maximalClosure":"0123456789abcdef0123456789abcdef","testVariantClosure":"fedcba9876543210fedcba9876543210","toolchain":"go1.27.0 linux/amd64","buildConfig":"b1","observationAssertion":"caller assertion","observationProof":{"strategy":"` + ObservationRTA + `","package":"example.com/m/p","symbol":"TestX","observable":false,"reason":"reaches os.Getenv","evidence":"00112233445566778899aabbccddeeff"},"purityAssertion":"source directive","dynamicStateVouches":"example.com/m/p.state","singleSubjectDischarges":"example.com/m/p.single","packageProcessDischarges":"example.com/m/p.proc","dynamicStateStrategy":"` + DynamicStateStrategy + `","closureStrategy":"` + ClosureStrategy + `","runtimeInputs":"manifest","runtimeDigest":"ffeeddccbbaa99887766554433221100","resultKind":1}`
	got, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("record form:\n got %s\nwant %s", got, want)
	}
	var back Fingerprint
	if err := json.Unmarshal([]byte(want), &back); err != nil {
		t.Fatal(err)
	}
	if back != full {
		t.Fatalf("decoded %+v\nwant    %+v", back, full)
	}
	// The minimal code-result record: the two hashes, the two code
	// guards, the kind — nothing else.
	minimal := Fingerprint{MaximalClosure: "a", TestVariantClosure: "b", Guards: guard.Guards{Toolchain: "t", BuildConfig: "c"}, ResultKind: CodeResult}
	got, err = json.Marshal(minimal)
	if err != nil || string(got) != `{"maximalClosure":"a","testVariantClosure":"b","toolchain":"t","buildConfig":"c","resultKind":1}` {
		t.Fatalf("minimal record = %s, %v", got, err)
	}
	// A measurement record carries its two measurement guards, and a
	// positive proof carries no reason key.
	measured := Fingerprint{MaximalClosure: "a", TestVariantClosure: "b", Guards: guard.Guards{Toolchain: "t", BuildConfig: "c", Machine: "m", RuntimeConfig: "r"}, ObservationAssertion: "caller assertion", ObservationProof: ObservationProof{Strategy: ObservationRTA, Subject: Subject{Package: "p", Symbol: "s"}, Observable: true, Evidence: "e"}, ResultKind: Measurement}
	got, err = json.Marshal(measured)
	if err != nil || string(got) != `{"maximalClosure":"a","testVariantClosure":"b","toolchain":"t","buildConfig":"c","machine":"m","runtimeConfig":"r","observationAssertion":"caller assertion","observationProof":{"strategy":"`+ObservationRTA+`","package":"p","symbol":"s","observable":true,"evidence":"e"},"resultKind":2}` {
		t.Fatalf("measurement record = %s, %v", got, err)
	}
	// The three strategy constants are interpolated, not spelled: each
	// carries its own golden (TestObservationRTAVersion,
	// TestDynamicStateStrategyVersion, TestClosureStrategyVersion), and
	// a derivation move is not a record-form move.
	//
	// The flattened types' shapes are the record's: a field added to any
	// of them would silently drop from the encoding, so each is pinned
	// beside the golden.
	shape := func(typ reflect.Type, want ...string) {
		t.Helper()
		var got []string
		for i := 0; i < typ.NumField(); i++ {
			got = append(got, typ.Field(i).Name+" "+typ.Field(i).Type.String())
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s fields = %v, want %v", typ, got, want)
		}
	}
	shape(reflect.TypeFor[guard.Guards](), "Toolchain string", "BuildConfig string", "Machine string", "RuntimeConfig string")
	shape(reflect.TypeFor[ObservationProof](), "Strategy string", "Subject gofresh.Subject", "Observable bool", "Reason string", "Evidence string")
	shape(reflect.TypeFor[Subject](), "Package string", "Symbol string")
	// The form owns its escaping: a parent encoder's escaping setting
	// leaves the bytes — and the value read back — unchanged.
	escaped := fullFingerprint()
	escaped.DynamicStateVouches = "a<b&c>d"
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(escaped); err != nil {
		t.Fatal(err)
	}
	own, err := json.Marshal(escaped)
	if err != nil || strings.TrimSpace(raw.String()) != string(own) || !strings.Contains(string(own), `\u003cb\u0026c\u003ed`) {
		t.Fatalf("escaping under a parent encoder: %q vs %q, %v", raw.String(), own, err)
	}
	var fromRaw Fingerprint
	if err := json.Unmarshal(raw.Bytes(), &fromRaw); err != nil || fromRaw != escaped {
		t.Fatalf("the escaped record read back: %v, %+v", err, fromRaw)
	}
	// A negative proof without a reason is incoherent to the check but
	// readable: it decodes.
	var negative Fingerprint
	if err := json.Unmarshal([]byte(`{"maximalClosure":"a","testVariantClosure":"b","toolchain":"t","buildConfig":"c","observationProof":{"strategy":"s","package":"p","symbol":"s","observable":false,"evidence":"e"},"resultKind":1}`), &negative); err != nil || negative.ObservationProof.Observable || negative.ObservationProof.Reason != "" {
		t.Fatalf("a negative proof without a reason: %+v, %v", negative, err)
	}
}

// genFingerprint draws a valid fingerprint: either kind, the proof
// present or absent, every optional value empty or set.
func genFingerprint(r *rand.Rand) Fingerprint {
	pick := func(vals ...string) string { return vals[r.Intn(len(vals))] }
	f := Fingerprint{
		MaximalClosure:           pick("m1", "m2"),
		TestVariantClosure:       pick("", "v1", "v2"),
		ObservationAssertion:     pick("", "caller assertion"),
		PurityAssertion:          pick("", "caller assertion", "source directive"),
		DynamicStateVouches:      pick("", "a.b", "a.b,c.d"),
		SingleSubjectDischarges:  pick("", "a.s"),
		PackageProcessDischarges: pick("", "a.p"),
		DynamicStateStrategy:     pick("", DynamicStateStrategy, "old"),
		ClosureStrategy:          pick("", ClosureStrategy),
		RuntimeInputs:            pick("", "manifest"),
		RuntimeDigest:            pick("", "d1"),
		Guards:                   guard.Guards{Toolchain: pick("", "t"), BuildConfig: pick("", "b")},
	}
	if r.Intn(2) == 0 {
		f.ResultKind = CodeResult
	} else {
		f.ResultKind = Measurement
		f.Guards.Machine = pick("", "m")
		f.Guards.RuntimeConfig = pick("", "r")
	}
	if r.Intn(2) == 0 {
		observable := r.Intn(2) == 0
		reason := ""
		if !observable {
			reason = pick("", "reaches os.Getenv")
		}
		f.ObservationProof = ObservationProof{Strategy: pick(ObservationRTA, "s"), Subject: Subject{Package: pick("p", ""), Symbol: pick("s", "")}, Observable: observable, Reason: reason, Evidence: pick("", "e")}
	}
	return f
}

// TestFingerprintRecordRoundTrips is the round-trip property over a
// seeded draw of valid fingerprints of both kinds: decode(encode(f)) is
// f, encode(decode(b)) is b, and an empty optional value is an absent
// key — the identity a consumer's record names depend on
// (REQ-fresh-fingerprint-record).
func TestFingerprintRecordRoundTrips(t *testing.T) {
	r := rand.New(rand.NewSource(274))
	optional := map[string]func(Fingerprint) string{
		"machine": func(f Fingerprint) string { return f.Guards.Machine }, "runtimeConfig": func(f Fingerprint) string { return f.Guards.RuntimeConfig },
		"observationAssertion": func(f Fingerprint) string { return f.ObservationAssertion }, "purityAssertion": func(f Fingerprint) string { return f.PurityAssertion },
		"dynamicStateVouches": func(f Fingerprint) string { return f.DynamicStateVouches }, "singleSubjectDischarges": func(f Fingerprint) string { return f.SingleSubjectDischarges },
		"packageProcessDischarges": func(f Fingerprint) string { return f.PackageProcessDischarges }, "dynamicStateStrategy": func(f Fingerprint) string { return f.DynamicStateStrategy },
		"closureStrategy": func(f Fingerprint) string { return f.ClosureStrategy }, "runtimeInputs": func(f Fingerprint) string { return f.RuntimeInputs }, "runtimeDigest": func(f Fingerprint) string { return f.RuntimeDigest },
	}
	for i := 0; i < 500; i++ {
		f := genFingerprint(r)
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("draw %d: %v", i, err)
		}
		var back Fingerprint
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("draw %d: %v over %s", i, err, data)
		}
		if back != f {
			t.Fatalf("draw %d: decode(encode) moved:\n%+v\n%+v", i, f, back)
		}
		again, err := json.Marshal(back)
		if err != nil || string(again) != string(data) {
			t.Fatalf("draw %d: encode(decode) moved: %s vs %s (%v)", i, again, data, err)
		}
		for key, read := range optional {
			present := strings.Contains(string(data), `"`+key+`":`)
			if present != (read(f) != "") {
				t.Fatalf("draw %d: key %q present=%v for value %q in %s", i, key, present, read(f), data)
			}
		}
		if strings.Contains(string(data), `"observationProof":`) != (f.ObservationProof != (ObservationProof{})) {
			t.Fatalf("draw %d: proof key presence in %s", i, data)
		}
		if strings.Contains(string(data), `"reason":`) != (f.ObservationProof.Reason != "") {
			t.Fatalf("draw %d: reason key presence in %s", i, data)
		}
		// The whitespace rule over every draw: the record indented by a
		// parent decodes to the same value.
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, data, "", "  "); err != nil {
			t.Fatal(err)
		}
		var fromPretty Fingerprint
		if err := json.Unmarshal(pretty.Bytes(), &fromPretty); err != nil || fromPretty != f {
			t.Fatalf("draw %d: the indented record: %v, %+v", i, err, fromPretty)
		}
	}
}

// TestFingerprintRecordRefusals pins every decode refusal by its
// wording and the encoder's refusal of an invalid fingerprint: an
// unknown key, a duplicated key, an explicit null, a proof without its
// observable, a positive proof carrying a reason, a zero kind, and a
// code-result record carrying a measurement guard — while a measurement
// record carrying both guards decodes (REQ-fresh-fingerprint-record,
// REQ-guard-selective-capture).
func TestFingerprintRecordRefusals(t *testing.T) {
	base := `"maximalClosure":"a","testVariantClosure":"b","toolchain":"t","buildConfig":"c"`
	cases := []struct{ record, want string }{
		{`{` + base + `,"resultKind":1,"extra":"x"}`, `unknown field "extra"`},
		{`{` + base + `,"resultKind":1,"toolchain":"t2"}`, `field "toolchain" is duplicated`},
		{`{` + base + `,"resultKind":1,"purityAssertion":null}`, `field "purityAssertion" is null`},
		{`{` + base + `,"resultKind":1,"observationProof":null}`, `field "observationProof" is null`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","evidence":"e"}}`, `carries no observable`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":true,"reason":"r","evidence":"e"}}`, `positive observation proof carries a reason`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":false,"reason":null,"evidence":"e"}}`, `observation proof field "reason" is null`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":false,"evidence":"e","evidence":"f"}}`, `gofresh: observation proof field "evidence" is duplicated`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":false,"evidence":"e","bogus":1}}`, `gofresh: observation proof: json: unknown field "bogus"`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":null,"evidence":"e"}}`, `gofresh: observation proof field "observable" is null`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":"yes","evidence":"e"}}`, `gofresh: observation proof field "observable" cannot hold a JSON string`},
		{`{` + base + `,"resultKind":true}`, `gofresh: fingerprint record field "resultKind" cannot hold a JSON bool`},
		{`{` + base + `,"resultKind":1,"extra":null}`, `gofresh: fingerprint record field "extra" is null`},
		// Bytes the encoder would not have written: a reordered record,
		// an empty-valued optional, a zero proof object (an indented one
		// decodes — see below).
		{`{"resultKind":1,"buildConfig":"c","toolchain":"t","testVariantClosure":"b","maximalClosure":"a"}`, `not the form's own encoding`},
		{`{` + base + `,"purityAssertion":"","resultKind":1}`, `not the form's own encoding`},
		{`{` + base + `,"observationProof":{"strategy":"","package":"","symbol":"","observable":false,"evidence":""},"resultKind":1}`, `not the form's own encoding`},
		{`{` + base + `}`, `invalid recorded result kind 0`},
		{`{` + base + `,"resultKind":3}`, `invalid recorded result kind 3`},
		{`{` + base + `,"resultKind":1,"machine":"m"}`, `code-result fingerprint carries measurement guards`},
		{`{` + base + `,"resultKind":1,"runtimeConfig":"r"}`, `code-result fingerprint carries measurement guards`},
		{`[]`, `not a JSON object`},
	}
	for _, c := range cases {
		var f Fingerprint
		err := json.Unmarshal([]byte(c.record), &f)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Count(err.Error(), "gofresh: ") != 1 || strings.Contains(err.Error(), "fingerprintRecord") || strings.Contains(err.Error(), "observationProofRecord") {
			t.Errorf("%s: err = %v, want %q, prefixed exactly once, naming no internal type", c.record, err, c.want)
		}
		if f != (Fingerprint{}) {
			t.Errorf("%s: a refused record left %+v", c.record, f)
		}
	}
	// An indented record decodes — a parent document is free to indent
	// its nested values — and the form composes with such a document:
	// the envelope a consumer writes with MarshalIndent round-trips.
	var indented Fingerprint
	if err := json.Unmarshal([]byte("{\n  "+base+`,`+"\n  "+`"resultKind":1`+"\n}"), &indented); err != nil || indented.MaximalClosure != "a" {
		t.Fatalf("an indented record: %v, %+v", err, indented)
	}
	type envelope struct {
		Version     int         `json:"version"`
		Fingerprint Fingerprint `json:"fingerprint"`
	}
	pretty, err := json.MarshalIndent(envelope{8, fullFingerprint()}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var back envelope
	if err := json.Unmarshal(pretty, &back); err != nil || back.Fingerprint != fullFingerprint() {
		t.Fatalf("the pretty-printed envelope: %v, %+v", err, back.Fingerprint)
	}
	// Trailing data after the object is refused by the decoder itself —
	// encoding/json refuses it before a top-level UnmarshalJSON runs, so
	// the arm is reached directly.
	var direct Fingerprint
	if err := direct.UnmarshalJSON([]byte(`{` + base + `,"resultKind":1} 1`)); err == nil || err.Error() != "gofresh: fingerprint record carries trailing data" || direct != (Fingerprint{}) {
		t.Fatalf("trailing data: %v, %+v", err, direct)
	}
	var measured Fingerprint
	if err := json.Unmarshal([]byte(`{`+base+`,"machine":"m","runtimeConfig":"r","resultKind":2}`), &measured); err != nil || measured.Guards.Machine != "m" || measured.Guards.RuntimeConfig != "r" || measured.ResultKind != Measurement {
		t.Fatalf("a measurement record with both guards: %+v, %v", measured, err)
	}
	// The encoder refuses what the decoder refuses, so an invalid
	// record is never written.
	for _, c := range []struct {
		f    Fingerprint
		want string
	}{
		{Fingerprint{MaximalClosure: "a"}, "gofresh: invalid recorded result kind 0"},
		{Fingerprint{MaximalClosure: "a", ResultKind: 7}, "gofresh: invalid recorded result kind 7"},
		{Fingerprint{MaximalClosure: "a", ResultKind: CodeResult, Guards: guard.Guards{Machine: "m"}}, "gofresh: code-result fingerprint carries measurement guards"},
		{Fingerprint{MaximalClosure: "a", ResultKind: CodeResult, Guards: guard.Guards{RuntimeConfig: "r"}}, "gofresh: code-result fingerprint carries measurement guards"},
	} {
		if _, err := json.Marshal(c.f); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("encoding %+v: err = %v, want %q", c.f, err, c.want)
		}
		if err := c.f.Validate(); err == nil || err.Error() != c.want {
			t.Errorf("Validate(%+v) = %v, want %q", c.f, err, c.want)
		}
	}
	if err := fullFingerprint().Validate(); err != nil {
		t.Fatal(err)
	}
	// A refusal's wording names the record, so a consumer's store can
	// attribute the fault to the file it read.
	var f Fingerprint
	if err := json.Unmarshal([]byte(`{`+base+`,"resultKind":1,"extra":1}`), &f); err == nil || !strings.HasPrefix(err.Error(), "gofresh: fingerprint record: ") {
		t.Fatalf("unknown-key wording = %v", fmt.Sprint(err))
	}
}
