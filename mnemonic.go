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
	"unicode"
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

	syllableStarts = [16]string{
		"", "k", "s", "t", "d", "n", "h", "b", "sh", "m", "f", "r", "g", "z",
		"l", "ch",
	}
	syllableMiddles = [16]string{
		"a", "i", "u", "e", "o", "au", "ei", "ai",
		"a", "i", "u", "e", "o", "au", "ei", "ai",
	}
	syllableEnds = [16]string{
		"l", "r", "s", "t", "", "g", "k", "f",
		"l", "r", "s", "t", "", "g", "k", "f",
	}
)

// Mnemonic generates a cryptographically-secure human-readable IP
// representation. IP must be a valid IPv4 or IPv6 and salt is recommended to be
// at least 40 chars long.
func Mnemonic(ip, salt string) string {
	// Avoids concatenating strings
	buf := make([]byte, len(ip)+len(salt))
	copy(buf, ip)
	copy(buf[len(ip):], salt)
	return FromBuffer(buf)
}

// Sames as Mnemonic, but hashes an arbitrary []byte
func FromBuffer(buf []byte) string {
	var (
		sum    = sha1.Sum(buf)
		result = make([]byte, 0, 32)
	)
	for i := 0; i < 4; i++ {
		// This takes 4 bytes instead of 5. It looks that way in the C++!
		j := binary.BigEndian.Uint32(sum[i*5:])

		result = append(result, mnemonicStarts[(j%256)/16]...)
		result = append(result, mnemonicEnds[j%16]...)
	}
	return string(result)
}

// Like FromBuffer(), but generates a somewhat more readable fantasy-ish name
func FantasyName(buf []byte) string {
	// Convert 20 byte sum to 9
	sum := sha1.Sum(buf)
	var short [9]byte
	for i := 0; i < 18; i++ {
		short[i%9] += sum[i]
	}

	result := make([]byte, 0, 32)
	var last byte
	for i := 0; i < 3; i++ {
		for j, arr := range [...][16]string{
			syllableStarts, syllableMiddles, syllableEnds,
		} {
			s := arr[short[(i*3+j)]%16]

			// Prevent repeating sequential letters for better readability
			if len(s) != 0 {
				if s[0] == last {
					result = result[:len(result)-1]
				}
				last = s[len(s)-1]
			}
			result = append(result, s...)
		}
	}

	// Capitalize
	result[0] = byte(unicode.ToUpper(rune(result[0])))

	return string(result)
}
