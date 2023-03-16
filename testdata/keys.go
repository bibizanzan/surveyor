
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
iaygEDMUbx6kTgXTBcKZ0jrWPKakayNZ/kigBwYFK4EEACOhgYkDgYYABADFuvLV
UoaCDGHcw5uNfdRIsvaLKuWSpLsl48eWGZAwdNG432GDVKduO+pceuE+8XzcyJb+
uMv+D2b11Q/LQUcHJwE6fqbm8m3EtDKPsoKs0u/XUJb0JsH4J8lkZzbUTjvGYamn
FFlRjzoB3Oxu8UQgb+MWPedtH9XYBbg9biz4jJLkXQ==
-----END EC PRIVATE KEY-----
`),
	"rsa": []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC8A6FGHDiWCSREAXCq6yBfNVr0xCVG2CzvktFNRpue+RXrGs/2
a6ySEJQb3IYquw7HlJgu6fg3WIWhOmHCjfpG0PrL4CRwbqQ2LaPPXhJErWYejcD8
Di00cF3677+G10KMZk9RXbmHtuBFZT98wxg8j+ZsBMqGM1+7yrWUvynswQIDAQAB
AoGAJMCk5vqfSRzyXOTXLGIYCuR4Kj6pdsbNSeuuRGfYBeR1F2c/XdFAg7D/8s5R
38p/Ih52/Ty5S8BfJtwtvgVY9ecf/JlU/rl/QzhG8/8KC0NG7KsyXklbQ7gJT8UT
Ojmw5QpMk+rKv17ipDVkQQmPaj+gJXYNAHqImke5mm/K/h0CQQDciPmviQ+DOhOq
2ZBqUfH8oXHgFmp7/6pXw80DpMIxgV3CwkxxIVx6a8lVH9bT/AFySJ6vXq4zTuV9
6QmZcZzDAkEA2j/UXJPIs1fQ8z/6sONOkU/BjtoePFIWJlRxdN35cZjXnBraX5UR
fFHkePv4YwqmXNqrBOvSu+w2WdSDci+IKwJAcsPRc/jWmsrJW1q3Ha0hSf/WG/Bu
X7MPuXaKpP/DkzGoUmb8ks7yqj6XWnYkPNLjCc8izU5vRwIiyWBRf4mxMwJBAILa
NDvRS0rjwt6lJGv7zPZoqDc65VfrK2aNyHx2PgFyzwrEOtuF57bu7pnvEIxpLTeM
z26i6XVMeYXAWZMTloMCQBbpGgEERQpeUknLBqUHhg/wXF6+lFA+vEGnkY+Dwab2
KCXFGd+SQ5GdUcEMe9isUH6DYj/6/yCDoFrXXmpQb+M=
-----END RSA PRIVATE KEY-----
`),
	"rsa-sha2-256": []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC8A6FGHDiWCSREAXCq6yBfNVr0xCVG2CzvktFNRpue+RXrGs/2
a6ySEJQb3IYquw7HlJgu6fg3WIWhOmHCjfpG0PrL4CRwbqQ2LaPPXhJErWYejcD8
Di00cF3677+G10KMZk9RXbmHtuBFZT98wxg8j+ZsBMqGM1+7yrWUvynswQIDAQAB
AoGAJMCk5vqfSRzyXOTXLGIYCuR4Kj6pdsbNSeuuRGfYBeR1F2c/XdFAg7D/8s5R
38p/Ih52/Ty5S8BfJtwtvgVY9ecf/JlU/rl/QzhG8/8KC0NG7KsyXklbQ7gJT8UT
Ojmw5QpMk+rKv17ipDVkQQmPaj+gJXYNAHqImke5mm/K/h0CQQDciPmviQ+DOhOq
2ZBqUfH8oXHgFmp7/6pXw80DpMIxgV3CwkxxIVx6a8lVH9bT/AFySJ6vXq4zTuV9
6QmZcZzDAkEA2j/UXJPIs1fQ8z/6sONOkU/BjtoePFIWJlRxdN35cZjXnBraX5UR
fFHkePv4YwqmXNqrBOvSu+w2WdSDci+IKwJAcsPRc/jWmsrJW1q3Ha0hSf/WG/Bu
X7MPuXaKpP/DkzGoUmb8ks7yqj6XWnYkPNLjCc8izU5vRwIiyWBRf4mxMwJBAILa
NDvRS0rjwt6lJGv7zPZoqDc65VfrK2aNyHx2PgFyzwrEOtuF57bu7pnvEIxpLTeM
z26i6XVMeYXAWZMTloMCQBbpGgEERQpeUknLBqUHhg/wXF6+lFA+vEGnkY+Dwab2
KCXFGd+SQ5GdUcEMe9isUH6DYj/6/yCDoFrXXmpQb+M=
-----END RSA PRIVATE KEY-----
`),
	"rsa-sha2-512": []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC8A6FGHDiWCSREAXCq6yBfNVr0xCVG2CzvktFNRpue+RXrGs/2
a6ySEJQb3IYquw7HlJgu6fg3WIWhOmHCjfpG0PrL4CRwbqQ2LaPPXhJErWYejcD8
Di00cF3677+G10KMZk9RXbmHtuBFZT98wxg8j+ZsBMqGM1+7yrWUvynswQIDAQAB
AoGAJMCk5vqfSRzyXOTXLGIYCuR4Kj6pdsbNSeuuRGfYBeR1F2c/XdFAg7D/8s5R
38p/Ih52/Ty5S8BfJtwtvgVY9ecf/JlU/rl/QzhG8/8KC0NG7KsyXklbQ7gJT8UT
Ojmw5QpMk+rKv17ipDVkQQmPaj+gJXYNAHqImke5mm/K/h0CQQDciPmviQ+DOhOq
2ZBqUfH8oXHgFmp7/6pXw80DpMIxgV3CwkxxIVx6a8lVH9bT/AFySJ6vXq4zTuV9
6QmZcZzDAkEA2j/UXJPIs1fQ8z/6sONOkU/BjtoePFIWJlRxdN35cZjXnBraX5UR
fFHkePv4YwqmXNqrBOvSu+w2WdSDci+IKwJAcsPRc/jWmsrJW1q3Ha0hSf/WG/Bu
X7MPuXaKpP/DkzGoUmb8ks7yqj6XWnYkPNLjCc8izU5vRwIiyWBRf4mxMwJBAILa
NDvRS0rjwt6lJGv7zPZoqDc65VfrK2aNyHx2PgFyzwrEOtuF57bu7pnvEIxpLTeM
z26i6XVMeYXAWZMTloMCQBbpGgEERQpeUknLBqUHhg/wXF6+lFA+vEGnkY+Dwab2
KCXFGd+SQ5GdUcEMe9isUH6DYj/6/yCDoFrXXmpQb+M=
-----END RSA PRIVATE KEY-----
`),
	"pkcs8": []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCitzS2KiRQTccf
VApb0mbPpo1lt29JjeLBYAehXHWfQ+w8sXpd8e04n/020spx1R94yg+v0NjXyh2R
NFXNBYdhNei33VJxUeKNlExaecvW2yxfuZqka+ZxT1aI8zrAsjh3Rwc6wayAJS4R
wZuzlDv4jZitWqwD+mb/22Zwq/WSs4YX5dUHDklfdWSVnoBfue8K/00n8f5yMTdJ
vFF0qAJwf9spPEHla0lYcozJk64CO5lRkqfLor4UnsXXOiA7aRIoaUSKa+rlhiqt