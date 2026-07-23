/* {{{ Copyright 2017 Paul Tagliamonte
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. }}} */

package rtls

import (
	"fmt"
)

const TLSHeaderLength = 5

/* This function is basically all most folks want to invoke out of this
 * jumble of bits. This will take an incoming TLS Client Hello (including
 * all the fuzzy bits at the beginning of it - fresh out of the socket) and
 * go ahead and give us the SNI Name they want. */
func GetHostname(data []byte) (string, error) {
	if len(data) == 0 || data[0] != 0x16 {
		return "", fmt.Errorf("doesn't look like a TLS Client Hello")
	}

	extensions, err := GetExtensionBlock(data)
	if err != nil {
		return "", err
	}
	sn, err := GetSNBlock(extensions)
	if err != nil {
		return "", err
	}
	sni, err := GetSNIBlock(sn)
	if err != nil {
		return "", err
	}
	return string(sni), nil
}

/* Given a Server Name TLS Extension block, parse out and return the SNI
 * (Server Name Indication) payload */
func GetSNIBlock(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("not enough bytes for server name list")
	}

	listLength := int(data[0])<<8 + int(data[1])
	if listLength > len(data)-2 {
		return nil, fmt.Errorf("server name list exceeds extension length")
	}
	data = data[2 : 2+listLength]

	for len(data) > 0 {
		if len(data) < 3 {
			return nil, fmt.Errorf("truncated server name entry")
		}
		nameLength := int(data[1])<<8 + int(data[2])
		if nameLength > len(data)-3 {
			return nil, fmt.Errorf("server name exceeds entry length")
		}
		if data[0] == 0x00 { /* SNI */
			if nameLength == 0 {
				return nil, fmt.Errorf("empty server name")
			}
			return data[3 : 3+nameLength], nil
		}
		data = data[3+nameLength:]
	}

	return []byte{}, fmt.Errorf(
		"finished parsing the SN block without finding an SNI",
	)
}

/* Given a TLS Extensions data block, go ahead and find the SN block */
func GetSNBlock(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return []byte{}, fmt.Errorf("not enough bytes to be an SN block")
	}
	extensionLength := int(data[0])<<8 + int(data[1])
	if extensionLength+2 > len(data) {
		return []byte{}, fmt.Errorf("extension looks bonkers")
	}
	data = data[2 : extensionLength+2]

	for len(data) > 0 {
		if len(data) < 4 {
			return nil, fmt.Errorf("truncated TLS extension")
		}
		length := int(data[2])<<8 + int(data[3])
		if length > len(data)-4 {
			return nil, fmt.Errorf("TLS extension exceeds extension block")
		}
		if data[0] == 0x00 && data[1] == 0x00 {
			return data[4 : 4+length], nil
		}
		data = data[4+length:]
	}

	return []byte{}, fmt.Errorf(
		"finished parsing the Extension block without finding an SN block",
	)
}

/* Given a raw TLS Client Hello, go ahead and find all the Extensions */
func GetExtensionBlock(data []byte) ([]byte, error) {
	/*   data[0]           - content type
	 *   data[1], data[2]  - major/minor version
	 *   data[3], data[4]  - total length
	 *   data[...38+5]     - start of SessionID (length bit)
	 *   data[38+5]        - length of SessionID
	 */
	index := TLSHeaderLength + 38
	if len(data) < index+1 {
		return []byte{}, fmt.Errorf("not enough bits to be a Client Hello")
	}

	/* Index is at SessionID Length bit */
	index++
	sessionIDLength := int(data[index-1])
	if sessionIDLength > len(data)-index {
		return []byte{}, fmt.Errorf("not enough bytes for the SessionID")
	}
	index += sessionIDLength

	/* Index is at Cipher List Length bits */
	if len(data)-index < 2 {
		return []byte{}, fmt.Errorf("not enough bytes for the Cipher List")
	}
	cipherListLength := int(data[index])<<8 + int(data[index+1])
	index += 2
	if cipherListLength > len(data)-index {
		return []byte{}, fmt.Errorf("not enough bytes for the Cipher List")
	}
	index += cipherListLength

	/* Index is now at the compression length bit */
	if len(data)-index < 1 {
		return []byte{}, fmt.Errorf("not enough bytes for the compression length")
	}
	compressionLength := int(data[index])
	index++
	if compressionLength > len(data)-index {
		return []byte{}, fmt.Errorf("not enough bytes for the compression methods")
	}
	index += compressionLength

	/* Now we're at the Extension length field. */
	if len(data)-index < 2 {
		return nil, fmt.Errorf("no extensions")
	}
	extensionLength := int(data[index])<<8 + int(data[index+1])
	if extensionLength > len(data)-(index+2) {
		return nil, fmt.Errorf("extensions exceed Client Hello length")
	}
	return data[index : index+2+extensionLength], nil
}

// vim: foldmethod=marker
