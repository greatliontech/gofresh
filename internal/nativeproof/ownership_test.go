package nativeproof

import (
	"context"
	"math"
	"reflect"
	"strconv"
	"testing"
)

// Err is a caller-controlled callback, even when it never cancels. These tests
// replace the exported Image container without accessing its private fields or
// introducing a data race.
type imageCallbackContext struct {
	context.Context
	calls int
	onErr func(int)
}

func (c *imageCallbackContext) Err() error {
	c.calls++
	if c.onErr != nil {
		c.onErr(c.calls)
	}
	return c.Context.Err()
}

func TestCheckOwnsImageContainer(t *testing.T) {
	a := image(t, hexBytes(t, "31c0c3")) // XOR EAX,EAX; RET: independent of entry bits.
	b := image(t, hexBytes(t, "89d8c3")) // MOV EAX,EBX; RET: depends on undeclared RBX.
	f := face(Masks{}, Masks{RAX: math.MaxUint64})
	p, err := Propose(t.Context(), a, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	// Both images have precisely the same proposed instruction sizes and edges.
	// Rechecking graph shape alone therefore cannot detect the substituted body.
	q, err := Propose(t.Context(), b, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, q) {
		t.Fatal("ownership counterexample requires identical graph inventories")
	}
	bad, err := Check(t.Context(), b, testEntry, f, p)
	requireRefusal(t, bad, err, "result-input-bound")

	count := &imageCallbackContext{Context: t.Context()}
	if _, err := Check(count, a, testEntry, f, p); err != nil {
		t.Fatal(err)
	}
	// Exercise every callback boundary, including the very first Err, the first
	// proposal-inventory callback after decoding, and the final publication check.
	for at := 1; at <= count.calls; at++ {
		t.Run(strconv.Itoa(at), func(t *testing.T) {
			supplied := *a
			replaced := false
			ctx := &imageCallbackContext{Context: t.Context(), onErr: func(call int) {
				if call == at {
					supplied = *b
					replaced = true
				}
			}}
			c, err := Check(ctx, &supplied, testEntry, f, p)
			if err != nil {
				t.Fatal(err)
			}
			if !replaced {
				t.Fatal("replacement callback was not reached")
			}
			assertCertificateImage(t, c, a)
		})
	}
}

func TestCertificateOwnsImageAfterCallerReplacement(t *testing.T) {
	a := image(t, hexBytes(t, "31c0c3"))
	b := image(t, hexBytes(t, "89d8c3"))
	supplied := *a
	c, err := prove(t, &supplied, testEntry, face(Masks{}, Masks{RAX: math.MaxUint64}))
	if err != nil {
		t.Fatal(err)
	}
	supplied = *b
	assertCertificateImage(t, c, a)
	supplied = Image{}
	assertCertificateImage(t, c, a)
}

func assertCertificateImage(t *testing.T, c Certificate, want *Image) {
	t.Helper()
	b, ok := c.Bound()
	if !ok || b.ImageDigest != want.digest {
		t.Fatal("certificate bound a replacement image rather than its checked bytes")
	}
	if c.checked.image.digest != want.digest || !reflect.DeepEqual(c.checked.image.data, want.data) || !reflect.DeepEqual(c.checked.image.loads, want.loads) {
		t.Fatal("certificate retained the replaceable caller-owned image container")
	}
}

func TestProposeOwnsImageContainer(t *testing.T) {
	a := image(t, hexBytes(t, "31c090c3"))
	b := image(t, hexBytes(t, "89d8c3"))
	f := face(Masks{}, Masks{RAX: math.MaxUint64})
	count := &imageCallbackContext{Context: t.Context()}
	want, err := Propose(count, a, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	for at := 1; at <= count.calls; at++ {
		t.Run(strconv.Itoa(at), func(t *testing.T) {
			supplied := *a
			replaced := false
			ctx := &imageCallbackContext{Context: t.Context(), onErr: func(call int) {
				if call == at {
					supplied = *b
					replaced = true
				}
			}}
			got, err := Propose(ctx, &supplied, testEntry, f)
			if err != nil {
				t.Fatal(err)
			}
			if !replaced || !reflect.DeepEqual(got, want) {
				t.Fatal("proposal traversed a replaced or mixed image")
			}
		})
	}
}
