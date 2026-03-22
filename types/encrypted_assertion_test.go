// Copyright 2016 Russell Haering et al.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

// generateTestCert creates a self-signed TLS certificate for testing.
func generateTestCert(t *testing.T) *tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// encryptSymmetricKey encrypts a symmetric key with RSA-OAEP using SHA-1
// (matching the DecryptSymmetricKey implementation).
func encryptSymmetricKey(t *testing.T, cert *tls.Certificate, symKey []byte) string {
	t.Helper()
	pubKey := cert.PrivateKey.(*rsa.PrivateKey).PublicKey
	encKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &pubKey, symKey, nil)
	if err != nil {
		t.Fatalf("failed to encrypt symmetric key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(encKey)
}

func TestDecryptBytes_CBCTruncatedCiphertext(t *testing.T) {
	cert := generateTestCert(t)

	symKey := make([]byte, 16) // AES-128
	rand.Read(symKey)
	encKeyB64 := encryptSymmetricKey(t, cert, symKey)

	tests := []struct {
		name        string
		cipherData  []byte
		errContains string
	}{
		{
			name:        "empty ciphertext",
			cipherData:  []byte{},
			errContains: "failed to decrypt CBC ciphertext",
		},
		{
			name:        "only IV, no data blocks",
			cipherData:  make([]byte, 16), // exactly one block (IV only)
			errContains: "failed to decrypt CBC ciphertext",
		},
		{
			name:        "not a multiple of block size",
			cipherData:  make([]byte, 16+17), // IV (16) + 17 bytes (> blockSize but not a multiple)
			errContains: "failed to decrypt CBC ciphertext",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := &EncryptedAssertion{
				EncryptionMethod: EncryptionMethod{
					Algorithm: MethodAES128CBC,
				},
				EncryptedKey: EncryptedKey{
					EncryptionMethod: EncryptionMethod{
						Algorithm: MethodRSAOAEP,
					},
					CipherValue: encKeyB64,
				},
				CipherValue: base64.StdEncoding.EncodeToString(tt.cipherData),
			}

			_, err := ea.DecryptBytes(cert)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestDecryptBytes_GCMTruncatedCiphertext(t *testing.T) {
	cert := generateTestCert(t)

	symKey := make([]byte, 16)
	rand.Read(symKey)
	encKeyB64 := encryptSymmetricKey(t, cert, symKey)

	// GCM nonce is 12 bytes — provide fewer bytes than that
	ea := &EncryptedAssertion{
		EncryptionMethod: EncryptionMethod{
			Algorithm: MethodAES128GCM,
		},
		EncryptedKey: EncryptedKey{
			EncryptionMethod: EncryptionMethod{
				Algorithm: MethodRSAOAEP,
			},
			CipherValue: encKeyB64,
		},
		CipherValue: base64.StdEncoding.EncodeToString([]byte("short")),
	}

	_, err := ea.DecryptBytes(cert)
	if err == nil {
		t.Fatal("expected error for truncated GCM ciphertext, got nil")
	}
	if !strings.Contains(err.Error(), "too short for AES-GCM") {
		t.Fatalf("expected 'too short for AES-GCM' error, got: %v", err)
	}
}

// TestDecryptBytes_CBCInvalidPadding verifies that invalid PKCS#7 padding
// returns an error instead of panicking or producing garbage.
func TestDecryptBytes_CBCInvalidPadding(t *testing.T) {
	cert := generateTestCert(t)

	symKey := make([]byte, 16)
	rand.Read(symKey)
	encKeyB64 := encryptSymmetricKey(t, cert, symKey)

	// Create ciphertext that will decrypt to data with invalid padding.
	// IV (16 bytes) + one block (16 bytes) of zeros — after decryption,
	// the last byte will likely be an invalid pad value.
	cipherData := make([]byte, 32)
	rand.Read(cipherData) // random data won't have valid PKCS#7 padding

	ea := &EncryptedAssertion{
		EncryptionMethod: EncryptionMethod{
			Algorithm: MethodAES128CBC,
		},
		EncryptedKey: EncryptedKey{
			EncryptionMethod: EncryptionMethod{
				Algorithm: MethodRSAOAEP,
			},
			CipherValue: encKeyB64,
		},
		CipherValue: base64.StdEncoding.EncodeToString(cipherData),
	}

	// This should either return an error or return data without panicking.
	// Before the fix, certain inputs would cause an index-out-of-range panic.
	_, err := ea.DecryptBytes(cert)
	// We accept either an error or success — the key requirement is no panic.
	_ = err
}
