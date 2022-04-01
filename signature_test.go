// Copyright 2022 lucasbbb. All rights reserved.
// Use of this source code is governed by an Apache 2.0
// license that can be found in the LICENSE file.

package jwa

import "testing"

func TestParseSignatureAlgorithm(t *testing.T) {
	type args struct {
		alg string
	}
	tests := []struct {
		name    string
		args    args
		want    SignatureAlgorithm
		wantErr bool
	}{
		{name: "HS256", args: args{alg: "HS256"}, want: HS256, wantErr: false},
		{name: "HS384", args: args{alg: "HS384"}, want: HS384, wantErr: false},
		{name: "HS512", args: args{alg: "HS512"}, want: HS512, wantErr: false},
		{name: "RS256", args: args{alg: "RS256"}, want: RS256, wantErr: false},
		{name: "RS384", args: args{alg: "RS384"}, want: RS384, wantErr: false},
		{name: "RS512", args: args{alg: "RS512"}, want: RS512, wantErr: false},
		{name: "ES256", args: args{alg: "ES256"}, want: ES256, wantErr: false},
		{name: "ES384", args: args{alg: "ES384"}, want: ES384, wantErr: false},
		{name: "ES512", args: args{alg: "ES512"}, want: ES512, wantErr: false},
		{name: "PS256", args: args{alg: "PS256"}, want: PS256, wantErr: false},
		{name: "PS384", args: args{alg: "PS384"}, want: PS384, wantErr: false},
		{name: "PS512", args: args{alg: "PS512"}, want: PS512, wantErr: false},
		{name: "None", args: args{alg: "none"}, want: None, wantErr: false},
		{name: "foo", args: args{alg: "foo"}, want: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSignatureAlgorithm(tt.args.alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignatureAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseSignatureAlgorithm() got = %v, want %v", got, tt.want)
			}
		})
	}
}
