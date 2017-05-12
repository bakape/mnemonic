package mnemonic

import (
	"io/ioutil"
	"strings"
	"testing"
)

const salt = "r088PUX0qpUjhUyZby6e4pQcDh3zzUQUpeLOy7Hb"

type inputCase struct {
	expected string
	input    string
}

func TestMnemonic(T *testing.T) {
	for _, test := range readCases("mnemonics_out") {
		res := Mnemonic(test.input, salt)
		if res != test.expected {
			T.Fatalf("%v : %s\n", test, res)
		}
		T.Log(test)
	}
}

func readCases(fileName string) (cases []inputCase) {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(file), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		cases = append(cases, inputCase{
			expected: fields[1],
			input:    fields[0],
		})
	}
	return
}
