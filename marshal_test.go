
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshmarshal

import (
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"

	"github.com/caarlos0/sshmarshal/testdata"
	. "golang.org/x/crypto/ssh"
)

var testPrivateKeys map[string]interface{}

func init() {
	n := len(testdata.PEMBytes)
	testPrivateKeys = make(map[string]interface{}, n)

	for t, k := range testdata.PEMBytes {
		var err error
		testPrivateKeys[t], err = ParseRawPrivateKey(k)
		if err != nil {
			panic(fmt.Sprintf("Unable to parse test key %s: %v", t, err))
		}
	}
}

func TestMarshalPrivateKey(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"rsa-openssh-format"},
		{"ed25519"},