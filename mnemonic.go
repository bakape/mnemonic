/*Package mnemonics makes textual representations out of IP adresses

Algorithm description:
Check of the IP is valid IPv4 or IPv6

Append the salt to the IP
SHA1 the IP
Split the SHA 1 in to 4 chunks of 5 bytes

For every chunk of 5 bytes take the first 4 bytes

Convert the 4 bytes to a hex representation
Convert the hex representation to a uint32

mod the uint32 by 256 and devide that by 16
Use this result as an index for the Mnemonic start array
Append the array index's value to the output result

mod the uint32 by 16
Use this result as an index for the Mnemonic end array
Append the array index's value to the output result

This will give you 8 appends in total the resulting array is your output
*/
package mnemonic

import (
	"crypto/sha1"
	"encoding/binary"
)

var (
	// Top nibble
	mnemonicStarts = [16]string{
		"", "k", "s", "t", "d", "n", "h", "b", "p", "m", "f", "r", "g", "z",
		"l", "ch",
	}

	// Bottom nibble
	mnemonicEnds = [16]string{
		"a", "i", "u", "e", "o", "a", "i", "u", "e", "o", "ya", "yi", "yu",
		"ye", "yo", "'",
	}
)

// Mnemonic generates a cryptographically-secure human-readable IP
// representation. IP must be a valid IPv4 or IPv6 and salt is recommended to be
// at least 40 chars long.
func Mnemonic(ip, salt string) string {
	var (
		sum    = sha1.Sum([]byte(ip + salt))
		result = make([]byte, 0, 8)
	)
	for i := 0; i < 4; i++ {
		// This takes 4 bytes instead of 5. It looks that way in the C++!
		j := binary.BigEndian.Uint32(sum[i*5:])

		result = append(result, mnemonicStarts[(j%256)/16]...)
		result = append(result, mnemonicEnds[j%16]...)
	}
	return string(result)
}
