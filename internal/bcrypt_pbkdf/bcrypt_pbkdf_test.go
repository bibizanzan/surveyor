// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bcrypt_pbkdf

import (
	"bytes"
	"testing"
)

// Test vectors generated by the reference implementation from OpenBSD.
var golden = []struct {
	rounds                 int
	password, salt, result []byte
}{
	{
		12,
		[]byte("password"),
		[]byte("salt"),
		[]byte{
			0x1a, 0xe4, 0x2c, 0x05, 0xd4, 0x87, 0xbc, 0x02, 0xf6,
			0x49, 0x21, 0xa4, 0xeb, 0xe4, 0xea, 0x93, 0xbc, 0xac,
			0xfe, 0x13, 0x5f, 0xda, 0x99, 0x97, 0x4c, 0x06, 0xb7,
			0xb0, 0x1f, 0xae, 0x14, 0x9a,
		},
	},
	{
		3,
		[]byte("passwordy\x00PASSWORD\x00"),
		[]byte("salty\x00SALT\x00"),
		[]byte{
			0x7f, 0x31, 0x0b, 0xd3, 0xe7, 0x8c, 0x32, 0x80, 0xc5,
			0x9c, 0xe4, 0x59, 0x52, 0x11, 0xa2, 0x92, 0x8e, 0x8d,
			0x4e, 0xc7, 0x44, 0xc1, 0xed, 0x2e, 0xfc, 0x9f, 0x76,
			0x4e, 0x33, 0x88, 0xe0, 0xad,
		},
	},
	{
		// See http://thread.gmane.org/gmane.os.openbsd.bugs/20542
		8,
		[]byte("секретное слово"),
		[]byte("посолить немножко"),
		[]byte{
			0x8d, 0xf4, 0x3f, 0xc6, 0xfe, 0x13, 0x1f, 0xc4, 0x7f,
			0x0c, 0x9e, 0x39, 0x22, 0x4b, 0xd9, 0x4c, 0x70, 0xb6,
			0xfc, 0xc8, 0xee, 0x81, 0x35, 0xfa, 0xdd, 0xf6, 0x11,
			0x56, 0xe6, 0xcb, 0x27, 0x33, 0xea, 0x76, 0x5f, 0x31,
			0x5a, 0x3e, 0x1e, 0x4a, 0xfc, 0x35, 0xbf, 0x86, 0x87,
			0xd1, 0x89, 0x25, 0x4c, 0x1e, 0x05, 0xa6, 0xfe, 0x80,
			0xc0, 0x61, 0x7f, 0x91, 0x83, 0xd6, 0x72, 0x60, 0xd6,
			0xa1, 0x15, 0xc6, 0xc9, 0x4e, 0x36, 0x03, 0xe2, 0x30,
			0x3f, 0xbb, 0x43, 0xa7, 0x6a, 0x64, 0x52, 0x3f, 0xfd,
			0xa6, 0x86, 0xb1, 0xd4, 0x51, 0x85, 0x43,
		},
	},
}

func TestKey(t *testing.T) {
	for i, v := range golden {
		k, err := Key(v.password, v.salt, v.rounds, len(v.result))
		if err != nil {
			t.Errorf("%d: %s", i, err)
			continue
		}
		if !bytes.Equal(k, v.result) {
			t.Errorf("%d: expected\n%x\n, got\n%x\n", i, v.result, k)
		}
	}
}

func TestBcryptHash(t *testing.T) {
	good := []byte{
		0x87, 0x90, 0x48, 0x70, 0xee, 0xf9, 0xde, 0xdd, 0xf8, 0xe7,
		0x61, 0x1a, 0x14, 0x01, 0x06, 0xe6, 0xaa, 0xf1, 0xa3, 0x63,
		0xd9, 0xa2, 0xc5, 