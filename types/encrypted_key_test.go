package types

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"strings"
	"testing"
)

func TestDecryptSymmetricKey(t *testing.T) {
	cert := generateTestCert(t)
	pubKey := cert.PrivateKey.(*rsa.PrivateKey).PublicKey

	t.Run("digest methods", func(t *testing.T) {
		tests := []struct {
			name      string
			algorithm string
			newHash   func() hash.Hash
		}{
			{"xmlenc sha256", "http://www.w3.org/2001/04/xmlenc#sha256", sha256.New},
			{"xmlenc sha512", "http://www.w3.org/2001/04/xmlenc#sha512", sha512.New},
			{"legacy xmldsig sha256", "http://www.w3.org/2000/09/xmldsig#sha256", sha256.New},
			{"legacy xmldsig sha512", "http://www.w3.org/2000/09/xmldsig#sha512", sha512.New},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				symKey := make([]byte, 16)
				if _, err := rand.Read(symKey); err != nil {
					t.Fatal(err)
				}
				encKey, err := rsa.EncryptOAEP(tt.newHash(), rand.Reader, &pubKey, symKey, nil)
				if err != nil {
					t.Fatalf("failed to encrypt symmetric key: %v", err)
				}

				ek := &EncryptedKey{
					CipherValue: base64.StdEncoding.EncodeToString(encKey),
					EncryptionMethod: EncryptionMethod{
						Algorithm:    MethodRSAOAEP,
						DigestMethod: &DigestMethod{Algorithm: tt.algorithm},
					},
				}
				if _, err := ek.DecryptSymmetricKey(cert); err != nil {
					t.Fatalf("expected the key to decrypt: %v", err)
				}
			})
		}
	})

	t.Run("unsupported digest method", func(t *testing.T) {
		ek := &EncryptedKey{
			CipherValue: base64.StdEncoding.EncodeToString([]byte("irrelevant")),
			EncryptionMethod: EncryptionMethod{
				Algorithm:    MethodRSAOAEP,
				DigestMethod: &DigestMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#sha384"},
			},
		}
		_, err := ek.DecryptSymmetricKey(cert)
		if err == nil || !strings.Contains(err.Error(), "unsupported digest algorithm") {
			t.Fatalf("expected an unsupported digest algorithm error, got: %v", err)
		}
	})
}
