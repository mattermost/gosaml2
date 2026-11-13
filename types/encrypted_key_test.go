package types

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"fmt"
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

	t.Run("mismatched cert reports a SHA-256 fingerprint", func(t *testing.T) {
		idpCert := generateTestCert(t)
		ek := &EncryptedKey{
			X509Data:    base64.StdEncoding.EncodeToString(idpCert.Certificate[0]),
			CipherValue: base64.StdEncoding.EncodeToString([]byte("irrelevant")),
		}
		_, err := ek.DecryptSymmetricKey(cert)
		if err == nil || !strings.Contains(err.Error(), "mismatched cert") {
			t.Fatalf("expected a mismatched cert error, got: %v", err)
		}
		// The error shows the first 11 characters of each fingerprint.
		for _, c := range []*tls.Certificate{cert, idpCert} {
			if want := debugKeyFp(c.Certificate[0])[:11]; !strings.Contains(err.Error(), want) {
				t.Fatalf("expected the error %q to contain the fingerprint prefix %q", err, want)
			}
		}
	})
}

func TestDebugKeyFp(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		if fp := debugKeyFp(nil); fp != "" {
			t.Fatalf("expected an empty fingerprint, got %q", fp)
		}
	})

	t.Run("colon-separated SHA-256", func(t *testing.T) {
		data := []byte("certificate bytes")
		sum := sha256.Sum256(data)
		parts := make([]string, len(sum))
		for i, b := range sum {
			parts[i] = fmt.Sprintf("%02x", b)
		}
		if got, want := debugKeyFp(data), strings.Join(parts, ":"); got != want {
			t.Fatalf("expected %q, got %q", want, got)
		}
	})
}
