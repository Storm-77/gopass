package crypto

import (
	"encoding/pem"
)

type CryptographicKey struct {
	public      []byte // in case Public is null this means there is symmettic algorithm in use
	private     []byte
	keyType     string
	isSymmetric bool
}

type CryptographicDevice interface {
	Encrypt(payload []byte) ([]byte, error)
	Decrypt(payload []byte) ([]byte, error)
	GetKey() (*CryptographicKey, error)
}

func (p CryptographicKey) IsSymmetric() bool {
	return p.isSymmetric
}

// returns (private-key, public-key) or (shared-secret, nil) for symetric algorithms
func (p CryptographicKey) ToPEM() ([]byte, []byte) {

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  p.keyType + " PRIVATE KEY",
		Bytes: p.private,
	})

	if p.isSymmetric {
		return privateKeyPEM, nil
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  p.keyType + " PUBLIC KEY",
		Bytes: p.public,
	})

	return privateKeyPEM, publicKeyPEM
}
