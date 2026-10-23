// Package jsonrecord provides the strict JSON object decoding and canonical
// byte-comparison primitives shared by gofresh's owned record formats
// (fingerprint records and runtime-input manifests).
package jsonrecord

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// UniqueObjectFields reads one JSON object's fields under object's noun,
// refusing a non-object, a duplicated key, or trailing data after the object.
func UniqueObjectFields(object string, data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("gofresh: %s is not a JSON object", object)
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("gofresh: %s: %w", object, err)
		}
		name, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("gofresh: %s: expected an object field", object)
		}
		if _, exists := fields[name]; exists {
			return nil, fmt.Errorf("gofresh: %s field %q is duplicated", object, name)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("gofresh: %s: %w", object, err)
		}
		fields[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("gofresh: %s: %w", object, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("gofresh: %s carries trailing data", object)
	}
	return fields, nil
}

// RejectNullFields refuses any field whose raw JSON value is null.
func RejectNullFields(object string, fields map[string]json.RawMessage) error {
	for name, value := range fields {
		if IsNull(value) {
			return fmt.Errorf("gofresh: %s field %q is null", object, name)
		}
	}
	return nil
}

// IsNull reports whether value is the JSON literal null (up to surrounding whitespace).
func IsNull(value json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

// DecodeObject decodes data into dst with unknown fields disallowed, formatting
// any decoding error under object's noun.
func DecodeObject(object string, data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return RecordFault(object, err)
	}
	return nil
}

// DecodeSingleValue decodes a single JSON value from data into dst with
// unknown fields disallowed and verifies that no trailing JSON tokens follow.
func DecodeSingleValue(prefix string, data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	return RequireEnd(dec, prefix)
}

// RequireEnd verifies that dec has reached EOF with no trailing JSON value.
func RequireEnd(dec *json.Decoder, prefix string) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s: trailing JSON value", prefix)
		}
		return fmt.Errorf("%s: %w", prefix, err)
	}
	return nil
}

// CanonicalEqual compares canonical JSON bytes against input data. When
// compactInput is true (nested records that a parent document may indent),
// insignificant whitespace in data is compacted before comparing; when false
// (framed records that are never nested), raw bytes must match exactly.
func CanonicalEqual(canonical, data []byte, compactInput bool) bool {
	if !compactInput {
		return bytes.Equal(canonical, data)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return false
	}
	return bytes.Equal(canonical, compact.Bytes())
}

// RecordFault names a decoding fault in the record's own vocabulary:
// gofresh-prefixed refusals pass through, a value of the wrong JSON kind
// names the field and kind, and anything else carries the object's noun.
func RecordFault(object string, err error) error {
	var typed *json.UnmarshalTypeError
	switch {
	case strings.HasPrefix(err.Error(), "gofresh: "):
		return err
	case errors.As(err, &typed):
		return fmt.Errorf("gofresh: %s field %q cannot hold a JSON %s", object, typed.Field, typed.Value)
	default:
		return fmt.Errorf("gofresh: %s: %w", object, err)
	}
}
