// Copyright 2022 lucasbbb. All rights reserved.
// Use of this source code is governed by an Apache 2.0
// license that can be found in the LICENSE file.

package jwa

import "fmt"

// SignatureAlgorithm is used to sign digitally or create a MAC.
// https://www.rfc-editor.org/rfc/rfc7518#section-3
type SignatureAlgorithm string

const (
	HS256 SignatureAlgorithm = "HS256" // HMAC using SHA-256
	HS384 SignatureAlgorithm = "HS384" // HMAC using SHA-384
	HS512 SignatureAlgorithm = "HS512" // HMAC using SHA-512
	RS256 SignatureAlgorithm = "RS256" // RSASSA-PKCS1-v1_5 using SHA-256
	RS384 SignatureAlgorithm = "RS384" // RSASSA-PKCS1-v1_5 using SHA-384
	RS512 SignatureAlgorithm = "RS512" // RSASSA-PKCS1-v1_5 using SHA-512
	ES256 SignatureAlgorithm = "ES256" // ECDSA using P-256 and SHA-256
	ES384 SignatureAlgorithm = "ES384" // ECDSA using P-384 and SHA-384
	ES512 SignatureAlgorithm = "ES512" // ECDSA using P-521 and SHA-512
	PS256 SignatureAlgorithm = "PS256" // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	PS384 SignatureAlgorithm = "PS384" // RSASSA-PSS using SHA-384 and MGF1 with SHA-384
	PS512 SignatureAlgorithm = "PS512" // RSASSA-PSS using SHA-512 and MGF1 with SHA-512
	None  SignatureAlgorithm = "none"  // No digital signature or MAC performed
)

func (v SignatureAlgorithm) String() string {
	return string(v)
}

var signatureAlgorithms = map[SignatureAlgorithm]struct{}{
	HS256: {},
	HS384: {},
	HS512: {},
	RS256: {},
	RS384: {},
	RS512: {},
	ES256: {},
	ES384: {},
	ES512: {},
	PS256: {},
	PS384: {},
	PS512: {},
	None:  {},
}

// ParseSignatureAlgorithm check whether the input alg is a valid alg string.
func ParseSignatureAlgorithm(alg string) (SignatureAlgorithm, error) {
	signAlg := SignatureAlgorithm(alg)
	if _, ok := signatureAlgorithms[signAlg]; !ok {
		return "", fmt.Errorf("invalid alg type: %s", alg)
	}
	return signAlg, nil
}
