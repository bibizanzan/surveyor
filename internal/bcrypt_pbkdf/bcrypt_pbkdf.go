// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bcrypt_pbkdf implements bcrypt_pbkdf(3) from OpenBSD.
//
// See https://flak.tedunangst.com/post/bcrypt-pbkdf and
// https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/lib/libutil/bcrypt_pbkdf.c.
package bcrypt_pbkdf

import (
	"crypto/sha512"
	"errors"
	"golang.org/x/crypto/blowfish"
)

const blockSize = 32

// Key derives a key from the password, salt and rounds count, returning a
// []byte of length keyLen that can be used as cryptographic key.
func Key(password, salt []byte, rounds, keyLen int) ([]by