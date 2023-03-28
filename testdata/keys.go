
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
1EMGYiBjblPt4SwMelGGU2UfywPb4d85gpQ/s8SBARbpPxNVs2IbHDMwj70P3uZc
74M3c4VJAgMBAAECggEAFIzY3mziGzZHgMBncoNXMsCRORh6uKpvygZr0EhSHqRA
cMXlc3n7gNxL6aGjqc7F48Z5RrY0vMQtCcq3T2Z0W6WoV5hfMiqqV0E0h3S8ds1F
hG13h26NMyBXCILXl8Cqev4Afr45IBISCHIQTRTaoiCX+MTr1rDIU2YNQQumvzkz
fMw2XiFTFTgxAtJUAgKoTqLtm7/T+az7TKw+Hesgbx7yaJoMh9DWGBh4Y61DnIDA
fcxJboAfxxnFiXvdBVmzo72pCsRXrWOsjW6WxQmCKuXHvyB1FZTmMaEFNCGSJDa6
U+OCzA3m65loAZAE7ffFHhYgssz/h9TBaOjKO0BX1QKBgQDZiCBvu+bFh9pEodcS
VxaI+ATlsYcmGdLtnZw5pxuEdr60iNWhpEcV6lGkbdiv5aL43QaGFDLagqeHI77b
+ITFbPPdCiYNaqlk6wyiXv4pdN7V683EDmGWSQlPeC9IhUilt2c+fChK2EB/XlkO
q8c3Vk1MsC6JOxDXNgJxylNpswKBgQC/fYBTb9iD+uM2n3SzJlct/ZlPaONKnNDR
pbTOdxBFHsu2VkfY858tfnEPkmSRX0yKmjHni6e8/qIzfzLwWBY4NmxhNZE5v+qJ
qZF26ULFdrZB4oWXAOliy/1S473OpQnp2MZp2asd0LPcg/BNaMuQrz44hxHb76R7
qWD0ebIfEwKBgQCRCIiP1pjbVGN7ZOgPS080DSC+wClahtcyI+ZYLglTvRQTLDQ7
LFtUykCav748MIADKuJBnM/3DiuCF5wV71EejDDfS/fo9BdyuKBY1brhixFTUX+E
Ww5Hc/SoLnpgALVZ/7jvWTpIBHykLxRziqYtR/YLzl+IkX/97P2ePoZ0rwKBgHNC
/7M5Z4JJyepfIMeVFHTCaT27TNTkf20x6Rs937U7TDN8y9JzEiU4LqXI4HAAhPoI
xnExRs4kF04YCnlRDE7Zs3Lv43J3ap1iTATfcymYwyv1RaQXEGQ/lUQHgYCZJtZz
fTrJoo5XyWu6nzJ5Gc8FLNaptr5ECSXGVm3Rsr2xAoGBAJWqEEQS/ejhO05QcPqh
y4cUdLr0269ILVsvic4Ot6zgfPIntXAK6IsHGKcg57kYm6W9k1CmmlA4ENGryJnR
vxyyqA9eyTFc1CQNuc2frKFA9It49JzjXahKc0aDHEHmTR787Tmk1LbuT0/gm9kA
L4INU6g+WqF0fatJxd+IJPrp
-----END PRIVATE KEY-----
`),
	"ed25519": []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACA+3f7hS7g5UWwXOGVTrMfhmxyrjqz7Sxxbx7I1j8DvvwAAAJhAFfkOQBX5
DgAAAAtzc2gtZWQyNTUxOQAAACA+3f7hS7g5UWwXOGVTrMfhmxyrjqz7Sxxbx7I1j8Dvvw
AAAEAaYmXltfW6nhRo3iWGglRB48lYq0z0Q3I3KyrdutEr6j7d/uFLuDlRbBc4ZVOsx+Gb
HKuOrPtLHFvHsjWPwO+/AAAAE2dhcnRvbm1AZ2FydG9ubS14cHMBAg==
-----END OPENSSH PRIVATE KEY-----
`),
	"rsa-openssh-format": []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAwa48yfWFi3uIdqzuf9X7C2Zxfea/Iaaw0zIwHudpF8U92WVIiC5l
oEuW1+OaVi3UWfIEjWMV1tHGysrHOwtwc34BPCJqJknUQO/KtDTBTJ4Pryhw1bWPC999Lz
a+yrCTdNQYBzoROXKExZgPFh9pTMi5wqpHDuOQ2qZFIEI3lT0AAAIQWL0H31i9B98AAAAH
c3NoLXJzYQAAAIEAwa48yfWFi3uIdqzuf9X7C2Zxfea/Iaaw0zIwHudpF8U92WVIiC5loE
uW1+OaVi3UWfIEjWMV1tHGysrHOwtwc34BPCJqJknUQO/KtDTBTJ4Pryhw1bWPC999Lza+
yrCTdNQYBzoROXKExZgPFh9pTMi5wqpHDuOQ2qZFIEI3lT0AAAADAQABAAAAgCThyTGsT4
IARDxVMhWl6eiB2ZrgFgWSeJm/NOqtppWgOebsIqPMMg4UVuVFsl422/lE3RkPhVkjGXgE