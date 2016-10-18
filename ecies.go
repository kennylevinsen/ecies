package ecies

import (
	"crypto/rand"
	"crypto/sha512"

	"golang.org/x/crypto/curve25519"
)

func Encrypt(plainText, publicKey []byte) ([]byte, error) {
	var r, R, S, K_B [32]byte

	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	r[0] &= 248
	r[31] &= 127
	r[31] |= 64

	copy(K_B[:], publicKey)

	curve25519.ScalarBaseMult(&R, &r)
	curve25519.ScalarMult(&S, &r, &K_B)
	k_E := sha512.Sum512(S[:])

	cipherText := make([]byte, 32+len(plainText))
	copy(cipherText[:32], R[:])
	for i := 0; i < len(plainText); i++ {
		cipherText[32+i] = plainText[i] ^ k_E[i]
	}

	return cipherText, nil
}

func Decrypt(cipherText, privateKey []byte) ([]byte, error) {
	var R, S, k_B [32]byte
	copy(R[:], cipherText[:32])
	copy(k_B[:], privateKey)

	curve25519.ScalarMult(&S, &k_B, &R)

	k_E := sha512.Sum512(S[:])

	plainText := make([]byte, len(cipherText)-32)
	for i := 0; i < len(plainText); i++ {
		plainText[i] = cipherText[32+i] ^ k_E[i]
	}

	return plainText, nil
}
