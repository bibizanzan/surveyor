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
		[]byt