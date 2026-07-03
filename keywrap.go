package main

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
)

// aesKeyWrapWithPadding implements RFC 5649 (AES Key Wrap with Padding).
//
//  1. Construct the AIV: 0xA65959A6 || uint32_be(len(plaintext))
//  2. Pad plaintext to a multiple of 8 bytes
//  3. If single block (n==1): return AES-ECB(KEK, AIV || padded)
//  4. If multiple blocks: apply RFC 3394 key wrap with AIV as the initial value
func aesKeyWrapWithPadding(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext must not be empty")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	// AIV = A65959A6 || uint32_be(len(plaintext))
	var aiv [8]byte
	aiv[0], aiv[1], aiv[2], aiv[3] = 0xA6, 0x59, 0x59, 0xA6
	binary.BigEndian.PutUint32(aiv[4:], uint32(len(plaintext)))

	// Pad to a multiple of 8 bytes with zero bytes.
	paddedLen := len(plaintext)
	if rem := paddedLen % 8; rem != 0 {
		paddedLen += 8 - rem
	}
	padded := make([]byte, paddedLen)
	defer zeroBytes(padded)
	copy(padded, plaintext)

	n := len(padded) / 8

	if n == 1 {
		// Single block: AES-ECB encrypt AIV || padded.
		var buf [aes.BlockSize]byte
		defer zeroBytes(buf[:])
		copy(buf[:8], aiv[:])
		copy(buf[8:], padded)
		block.Encrypt(buf[:], buf[:])

		result := make([]byte, aes.BlockSize)
		copy(result, buf[:])
		return result, nil
	}

	// Multiple blocks: RFC 3394 key wrap with AIV as the initial A value.
	r := make([][]byte, n)
	defer zeroByteSlices(r)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], padded[i*8:(i+1)*8])
	}

	a := make([]byte, 8)
	copy(a, aiv[:])

	var buf [aes.BlockSize]byte
	defer zeroBytes(buf[:])
	for j := 0; j <= 5; j++ {
		for i := 0; i < n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i])
			block.Encrypt(buf[:], buf[:])

			copy(a, buf[:8])
			t := uint64(n*j + i + 1)
			for k := 0; k < 8; k++ {
				a[k] ^= byte(t >> (56 - 8*k))
			}
			copy(r[i], buf[8:])
		}
	}

	result := make([]byte, 0, 8+n*8)
	result = append(result, a...)
	for _, ri := range r {
		result = append(result, ri...)
	}
	return result, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func zeroByteSlices(slices [][]byte) {
	for _, b := range slices {
		zeroBytes(b)
	}
}
