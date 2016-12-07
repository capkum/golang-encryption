package cfb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// CfbEncrypter 암호화
// text 암호화할 string,  key 16배수의 byte slice
func CfbEncrypter(text string, key []byte) string {
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err.Error())
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return fmt.Sprintf("%x", ciphertext)
}

// CfbDecrypter 복호화
// descryptext 암호화된 string, key 16배수의 byte slice
func CfbDecrypter(descryptext string, key []byte) string {
	ciphertext, _ := hex.DecodeString(descryptext)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	if len(ciphertext) < aes.BlockSize {
		panic("암호화된 text가 넘 짧습니다")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	// fmt.Printf("%s", ciphertext)
	return fmt.Sprintf("%s", ciphertext)
}
