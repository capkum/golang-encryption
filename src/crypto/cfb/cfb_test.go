package cfb

import (
	"crypto/aes"
	"testing"
)

// TestCfbEncrypter 암호화 테스트 함수
// key 8 배수의 길이여야한다 16 24 32 64 ...
func TestCfbEncrypter(t *testing.T) {
	key := []byte("capture1capture1")
	_, err := aes.NewCipher(key)

	// key test
	if err != nil {
		t.Error(err.Error())
		return
	}

	rt1 := CfbEncrypter("Hello capkum!!", key)
	if len(rt1) != 60 {
		t.Error("암호화 실패")
	} else {
		t.Log("암호화 : ", rt1)
	}
}

// TestCfbDecrypter 복호화 테스트 함수
// key 8 배수의 길이여야한다 16 24 32 64 ...
func TestCfbDecrypter(t *testing.T) {
	key := []byte("capture1capture1")
	_, err := aes.NewCipher(key)

	// key test
	if err != nil {
		t.Error(err.Error())
		return
	}

	rt1 := CfbEncrypter("Hello capkum!!", key)
	if "Hello capkum!!" != CfbDecrypter(rt1, key) {
		t.Error("복호화 실패")
	} else {
		t.Log("복호화 : ", CfbDecrypter(rt1, key))
	}

}
