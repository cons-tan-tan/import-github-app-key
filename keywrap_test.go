package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// Test vectors from RFC 5649 Section 6.
// KEK is 192-bit AES key for both test cases.

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}
	return b
}

func TestAESKeyWrapWithPadding_RFC5649_Vector1(t *testing.T) {
	// RFC 5649 Section 6 - 20 bytes of plaintext with 192-bit KEK.
	kek := mustDecodeHex(t, "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
	plaintext := mustDecodeHex(t, "c37b7e6492584340bed1220780894115"+
		"5068f738")
	expected := mustDecodeHex(t, "138bdeaa9b8fa7fc61f97742e72248ee"+
		"5ae6ae5360d1ae6a5f54f373fa543b6a")

	result, err := aesKeyWrapWithPadding(kek, plaintext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, expected) {
		t.Errorf("mismatch\n  got:  %x\n  want: %x", result, expected)
	}
}

func TestAESKeyWrapWithPadding_RFC5649_Vector2(t *testing.T) {
	// RFC 5649 Section 6 - 7 bytes of plaintext with 192-bit KEK.
	kek := mustDecodeHex(t, "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
	plaintext := mustDecodeHex(t, "466f7250617369")
	expected := mustDecodeHex(t, "afbeb0f07dfbf5419200f2ccb50bb24f")

	result, err := aesKeyWrapWithPadding(kek, plaintext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, expected) {
		t.Errorf("mismatch\n  got:  %x\n  want: %x", result, expected)
	}
}

func TestAESKeyWrapWithPadding_RoundTrip(t *testing.T) {
	for _, keySize := range []int{16, 24, 32} {
		for _, size := range []int{1, 8, 9, 16, 17, 1217} {
			t.Run(fmt.Sprintf("key=%d/plaintext=%d", keySize, size), func(t *testing.T) {
				kek := bytes.Repeat([]byte{0x42}, keySize)
				plaintext := bytes.Repeat([]byte{0xAB}, size)
				original := bytes.Clone(plaintext)

				wrapped, err := aesKeyWrapWithPadding(kek, plaintext)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(plaintext, original) {
					t.Fatal("wrapping modified the input plaintext")
				}
				unwrapped, err := aesKeyUnwrapWithPadding(kek, wrapped)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(unwrapped, original) {
					t.Fatal("unwrapped key does not match the input plaintext")
				}
			})
		}
	}
}

func TestAESKeyWrapWithPadding_InvalidKEK(t *testing.T) {
	// KEK with invalid length (15 bytes) should fail.
	kek := make([]byte, 15)
	plaintext := []byte("test")

	_, err := aesKeyWrapWithPadding(kek, plaintext)
	if err == nil {
		t.Fatal("expected error for invalid KEK size, got nil")
	}
}
