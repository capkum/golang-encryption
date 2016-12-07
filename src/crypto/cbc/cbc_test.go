package cbc

import (
	"crypto/aes"
	"testing"
)

// TestCbcEncrypter 암호화 테스트
// key 8 배수의 길이여야한다 16 24 32 64 ...
// https://golang.org/pkg/crypto/aes/
func TestCbcEncrypter(t *testing.T) {
	key := []byte("example key 1234")
	_, err := aes.NewCipher(key)

	// key test
	if err != nil {
		t.Error(err.Error())
		return
	}

	rt_crypt := CbcEncrypter("capture1capture1", key)
	rt_length := len(rt_crypt)
	if rt_length != 64 {
		t.Error("암호화 되지 않았습니다")
	}

}

// TestCbcDecrypter 복호화 테스트
// key 8 배수의 길이여야한다 16 24 32 64 ...
func TestCbcDecrypter(t *testing.T) {
	key := []byte("example key 1234")
	_, err := aes.NewCipher(key)

	// key test
	if err != nil {
		t.Error(err.Error())
		return
	}

	test_string := "capture1capture1"
	rt_crypt := CbcEncrypter(test_string, key)
	rt_length := len(rt_crypt)
	if rt_length != 64 {
		t.Error("암호화 되지 않았습니다")
	}

	if test_string == CbcDecrypter(rt_crypt, key) {
		t.Error("복호화 에러입니다.")
	}

}
