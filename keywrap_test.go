package main

import (
	"bytes"
	"encoding/hex"
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

func TestAESKeyWrapWithPadding_SingleBlock(t *testing.T) {
	// 8 bytes of plaintext triggers the single-block (n==1) path.
	kek := make([]byte, 16) // AES-128 zero key
	plaintext := []byte("12345678")

	result, err := aesKeyWrapWithPadding(kek, plaintext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Single block output is always 16 bytes (AIV + 1 block encrypted together).
	if len(result) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(result))
	}
}

func TestAESKeyWrapWithPadding_MultiBlock_NoPadding(t *testing.T) {
	// 16 bytes of plaintext = exactly 2 blocks, no padding needed.
	kek := make([]byte, 32) // AES-256 zero key
	plaintext := []byte("0123456789ABCDEF")

	result, err := aesKeyWrapWithPadding(kek, plaintext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Output: 8 (A) + 16 (2 blocks) = 24 bytes.
	if len(result) != 24 {
		t.Errorf("expected 24 bytes, got %d", len(result))
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
