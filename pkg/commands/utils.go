package commands

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
)

func cryptoReader(r io.Reader, key []byte) io.Reader {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	return cipher.StreamReader{S: stream, R: r}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func Prompt(message string, args ...interface{}) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf(message, args...)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func ValidateMAC(message, messageMAC, key []byte) bool {
	expectedMAC := CreateMAC(message, key)
	return hmac.Equal(messageMAC, expectedMAC)
}

func CreateMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}
