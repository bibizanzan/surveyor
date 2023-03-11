
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testdata

var PEMBytes = map[string][]byte{
	"dsa": []byte(`-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQD6PDSEyXiI9jfNs97WuM46MSDCYlOqWw80ajN16AohtBncs1YB
lHk//dQOvCYOsYaE+gNix2jtoRjwXhDsc25/IqQbU1ahb7mB8/rsaILRGIbA5WH3
EgFtJmXFovDz3if6F6TzvhFpHgJRmLYVR8cqsezL3hEZOvvs2iH7MorkxwIVAJHD
nD82+lxh2fb4PMsIiaXudAsBAoGAQRf7Q/iaPRn43ZquUhd6WwvirqUj+tkIu6eV
2nZWYmXLlqFQKEy4Tejl7Wkyzr2OSYvbXLzo7TNxLKoWor6ips0phYPPMyXld14r
juhT24CrhOzuLMhDduMDi032wDIZG4Y+K7ElU8Oufn8Sj5Wge8r6ANmmVgmFfynr
FhdYCngCgYEA3ucGJ93/Mx4q4eKRDxcWD3QzWyqpbRVRRV1Vmih9Ha/qC994nJFz
DQIdjxDIT2Rk2AGzMqFEB68Zc3O+Wcsmz5eWWzEwFxaTwOGWTyDqsDRLm3fD+QYj
nOwuxb0Kce+gWI8voWcqC9cyRm09jGzu2Ab3Bhtpg8JJ8L7gS3MRZK4CFEx4UAfY
Fmsr0W6fHB9nhS4/UXM8
-----END DSA PRIVATE KEY-----
`),
	"ecdsa": []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINGWx0zo6fhJ/0EAfrPzVFyFC9s18lBt3cRoEDhS3ARooAoGCCqGSM49
AwEHoUQDQgAEi9Hdw6KvZcWxfg2IDhA7UkpDtzzt6ZqJXSsFdLd+Kx4S3Sx4cVO+
6/ZOXRnPmNAlLUqjShUsUBBngG0u2fqEqA==
-----END EC PRIVATE KEY-----
`),
	"ecdsap256": []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAPCE25zK0PQSnsgVcEbM1mbKTASH4pqb5QJajplDwDZoAoGCCqGSM49
AwEHoUQDQgAEWy8TxGcIHRh5XGpO4dFVfDjeNY+VkgubQrf/eyFJZHxAn1SKraXU
qJUjTKj1z622OxYtJ5P7s9CfAEVsTzLCzg==
-----END EC PRIVATE KEY-----
`),
	"ecdsap384": []byte(`-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBWfSnMuNKq8J9rQLzzEkx3KAoEohSXqhE/4CdjEYtoU2i22HW80DDS
qQhYNHRAduygBwYFK4EEACKhZANiAAQWaDMAd0HUd8ZiXCX7mYDDnC54gwH/nG43
VhCUEYmF7HMZm/B9Yn3GjFk3qYEDEvuF/52+NvUKBKKaLbh32AWxMv0ibcoba4cz
hL9+hWYhUD9XIUlzMWiZ2y6eBE9PdRI=
-----END EC PRIVATE KEY-----
`),
	"ecdsap521": []byte(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBrkYpQcy8KTVHNiAkjlFZwee90224Bu6wz94R4OBo+Ts0eoAQG7SF