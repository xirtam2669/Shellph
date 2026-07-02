package cryptoops

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"fmt"
)

func RC4(key []byte, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("RC4 key cannot be empty")
	}
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

func AESCBCEncrypt(key []byte, iv []byte, data []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("AES key must be 16, 24, or 32 bytes")
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("AES IV must be exactly 16 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded := pkcs7Pad(data, aes.BlockSize)
	out := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out, padded)
	return out, nil
}

func XOR(key []byte, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("XOR key cannot be empty")
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}
