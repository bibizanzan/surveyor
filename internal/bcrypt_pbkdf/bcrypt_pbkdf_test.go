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
			0x0c,