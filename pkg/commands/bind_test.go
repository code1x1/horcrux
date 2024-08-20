package commands

import (
	"io"
	"strings"
	"testing"
)

type result struct {
	ok        bool
	failIndex int
}

type signatureTest struct {
	reader         io.Reader
	signatures     [][]byte
	key            []byte
	expectedResult result
}

var signatureTests = []signatureTest{
	{
		reader:         strings.NewReader(""),
		signatures:     [][]byte{[]byte("")},
		key:            []byte(""),
		expectedResult: result{ok: false},
	},
	{
		reader:         strings.NewReader("dasasd"),
		signatures:     [][]byte{[]byte("dasasd")},
		key:            []byte("qweqwe"),
		expectedResult: result{ok: false},
	},
	{
		reader:         strings.NewReader("Alohomora"),
		signatures:     [][]byte{[]byte("QCNGEsxRAQeAH5RgH61zSH0Z5Tg6j3kfyijoQxjoZw0=")},
		key:            []byte{210, 210, 34, 138, 168, 48, 151, 180, 42, 157, 136, 250, 132, 35, 234, 238, 10, 60, 234, 230, 79, 24, 54, 121, 183, 24, 3, 85, 77, 88, 21, 192},
		expectedResult: result{ok: true},
	},
}

func TestValidateHorcruxSignatures(t *testing.T) {
	for _, test := range signatureTests {
		if ok, i := ValidateHorcruxSignatures(test.reader, test.signatures, test.key); ok != test.expectedResult.ok {
			t.Errorf("Output %v not expected for signature %d", ok, i)
		}
	}
}
