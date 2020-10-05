package azurekeyvault

import (
	"crypto/rsa"
	"math/big"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest/to"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

func Test_jwkToRSAPublicKey(t *testing.T) {
	type args struct {
		jwk *keyvault.JSONWebKey
	}
	tests := []struct {
		name    string
		args    args
		want    *rsa.PublicKey
		wantErr bool
	}{
		{
			name:    "nil JSONWebKey",
			args:    args{},
			wantErr: true,
		},
		{
			name: "invalid JSONWebKey missing N",
			args: args{
				&keyvault.JSONWebKey{
					E: to.StringPtr("AQAB"),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid JSONWebKey missing E",
			args: args{
				&keyvault.JSONWebKey{
					N: to.StringPtr("AQAB"),
				},
			},
			wantErr: true,
		},
		{
			name: "valid JSONWebKey",
			args: args{
				&keyvault.JSONWebKey{
					N: to.StringPtr("AAEAAQ"),
					E: to.StringPtr("AQAB"),
				},
			},
			want: &rsa.PublicKey{
				// "AAEAAQ" -> []byte{0,1,0,1} -> 65537
				// "AQAB"   -> []byte{1,0,1}   -> 65537
				// "AAEAAQ" and "AQAB" are equivalent after read big-endian
				N: big.NewInt(65537),
				E: 65537,
			},
		},
		{
			name: "valid JSONWebKey",
			args: args{
				&keyvault.JSONWebKey{
					N: to.StringPtr("AQAB"),
					E: to.StringPtr("AAEAAQ"),
				},
			},
			want: &rsa.PublicKey{
				// "AAEAAQ" -> []byte{0,1,0,1} -> 65537
				// "AQAB"   -> []byte{1,0,1}   -> 65537
				// "AAEAAQ" and "AQAB" are equivalent after read big-endian
				N: big.NewInt(0).SetBytes([]byte{1, 0, 1}),
				E: int(big.NewInt(0).SetBytes([]byte{1, 0, 1}).Int64()),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jwkToRSAPublicKey(tt.args.jwk)
			if (err != nil) != tt.wantErr {
				t.Errorf("jwkToRSAPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("jwkToRSAPublicKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWrapper_validateKMSKey(t *testing.T) {
	type args struct {
		key wrapping.KMSKey
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid KMS key single-purpose",
			args: args{
				wrapping.KMSKey{
					Type: wrapping.RSA3072,
					Purposes: []wrapping.Purpose{
						wrapping.Sign,
					},
					ProtectionLevel: wrapping.HSM,
					Material: wrapping.KeyMaterial{
						RSAKey: &rsa.PrivateKey{},
					},
				},
			},
		},
		{
			name: "valid KMS key multi-purpose",
			args: args{
				wrapping.KMSKey{
					Type: wrapping.RSA2048,
					Purposes: []wrapping.Purpose{
						wrapping.Encrypt,
						wrapping.Decrypt,
					},
					ProtectionLevel: wrapping.HSM,
					Material: wrapping.KeyMaterial{
						RSAKey: &rsa.PrivateKey{},
					},
				},
			},
		},
		{
			name: "valid KMS key multi-purpose",
			args: args{
				wrapping.KMSKey{
					Type: wrapping.RSA3072,
					Purposes: []wrapping.Purpose{
						wrapping.Sign,
						wrapping.Verify,
					},
					ProtectionLevel: wrapping.HSM,
					Material: wrapping.KeyMaterial{
						RSAKey: &rsa.PrivateKey{},
					},
				},
			},
		},
		{
			name: "valid KMS key multi-purpose",
			args: args{
				wrapping.KMSKey{
					Type: wrapping.RSA3072,
					Purposes: []wrapping.Purpose{
						wrapping.Unwrap,
						wrapping.Wrap,
					},
					ProtectionLevel: wrapping.HSM,
					Material: wrapping.KeyMaterial{
						RSAKey: &rsa.PrivateKey{},
					},
				},
			},
		},
		{
			name: "invalid KMS key empty purpose",
			args: args{
				wrapping.KMSKey{
					Type:            wrapping.RSA2048,
					Purposes:        []wrapping.Purpose{},
					ProtectionLevel: wrapping.HSM,
					Material: wrapping.KeyMaterial{
						RSAKey: &rsa.PrivateKey{},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid KMS key protection level",
			args: args{
				wrapping.KMSKey{
					Type: wrapping.RSA2048,
					Purposes: []wrapping.Purpose{
						wrapping.Decrypt,
					},
					ProtectionLevel: wrapping.Software,
					Material: wrapping.KeyMaterial{
						RSAKey: &rsa.PrivateKey{},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid KMS key unsupported type",
			args: args{
				wrapping.KMSKey{
					Type: wrapping.KeyType("aes_256"),
					Purposes: []wrapping.Purpose{
						wrapping.Decrypt,
					},
					ProtectionLevel: wrapping.Software,
					Material: wrapping.KeyMaterial{
						RSAKey: &rsa.PrivateKey{},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid KMS key unsupported purpose",
			args: args{
				wrapping.KMSKey{
					Type: wrapping.RSA2048,
					Purposes: []wrapping.Purpose{
						wrapping.Purpose("invalid"),
					},
					ProtectionLevel: wrapping.Software,
					Material: wrapping.KeyMaterial{
						RSAKey: &rsa.PrivateKey{},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Wrapper{}
			if err := v.validateKMSKey(tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("validateKMSKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWrapper_keyPurposesToKeyOps(t *testing.T) {
	type args struct {
		purposes []wrapping.Purpose
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "empty purpose",
			args: args{
				purposes: []wrapping.Purpose{},
			},
			want: []string{},
		},
		{
			name: "unsupported purpose",
			args: args{
				purposes: []wrapping.Purpose{wrapping.Purpose("unsupported")},
			},
			want: []string{},
		},
		{
			name: "single purpose",
			args: args{
				purposes: []wrapping.Purpose{wrapping.Encrypt},
			},
			want: []string{"encrypt"},
		},
		{
			name: "multiple purposes",
			args: args{
				purposes: []wrapping.Purpose{
					wrapping.Encrypt,
					wrapping.Decrypt,
					wrapping.Sign,
					wrapping.Verify,
					wrapping.Wrap,
					wrapping.Unwrap,
				},
			},
			want: []string{
				"encrypt",
				"decrypt",
				"sign",
				"verify",
				"wrapKey",
				"unwrapKey",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Wrapper{}
			if got := v.keyPurposesToKeyOps(tt.args.purposes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("keyPurposesToKeyOps() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWrapper_keyTypeToKty(t *testing.T) {
	type args struct {
		kt wrapping.KeyType
	}
	tests := []struct {
		name string
		args args
		want keyvault.JSONWebKeyType
	}{
		{
			name: "empty key type",
			args: args{
				kt: wrapping.KeyType(""),
			},
			want: keyvault.JSONWebKeyType(""),
		},
		{
			name: "RSA2048 key type",
			args: args{
				kt: wrapping.RSA2048,
			},
			want: keyvault.RSAHSM,
		},
		{
			name: "RSA3072 key type",
			args: args{
				kt: wrapping.RSA3072,
			},
			want: keyvault.RSAHSM,
		},
		{
			name: "RSA4096 key type",
			args: args{
				kt: wrapping.RSA4096,
			},
			want: keyvault.RSAHSM,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Wrapper{}
			if got := v.keyTypeToKty(tt.args.kt); got != tt.want {
				t.Errorf("keyTypeToKty() = %v, want %v", got, tt.want)
			}
		})
	}
}
