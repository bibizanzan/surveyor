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
func Key(password, salt []byte, rounds, keyLen int) ([]byte, error) {
	if rounds < 1 {
		return nil, errors.New("bcrypt_pbkdf: number of rounds is too small")
	}
	if len(password) == 0 {
		return nil, errors.New("bcrypt_pbkdf: empty password")
	}
	if len(salt) == 0 || len(salt) > 1<<20 {
		return nil, errors.New("bcrypt_pbkdf: bad salt length")
	}
	if keyLen > 1024 {
		return nil, errors.New("bcrypt_pbkdf: keyLen is too large")
	}

	numBlocks := (keyLen + blockSize - 1) / blockSize
	key := make([]byte, numBlocks*blockSize)

	h := sha512.New()
	h.Write(password)
	shapass := h.Sum(nil)

	shasalt := make([]byte, 0, sha512.Size)
	cnt, tmp := make([]byte, 4), make([]byte, blockSize)
	for block := 1; block <= numBlocks; block++ {
		h.Reset()
		h.Write(s