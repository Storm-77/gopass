package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type RsaCryptographicDevice struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func (p *RsaCryptographicDevice) Encrypt(payload []byte) ([]byte, error) {

	var publicKey *rsa.PublicKey = p.publicKey
	if publicKey == nil {
		p.publicKey = &p.privateKey.PublicKey
		publicKey = p.publicKey
	}

	encryptedPayload, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, payload)
	if err != nil {
		return nil, err
	}

	return encryptedPayload, nil
}

func (p *RsaCryptographicDevice) Decrypt(encrypted_payload []byte) ([]byte, error) {

	if p.privateKey == nil {
		return nil, errors.New("This encryption device cannot decrypt a message, it has no private key")
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, p.privateKey, encrypted_payload)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (p *RsaCryptographicDevice) GetKey() (*CryptographicKey, error) {
	// handle scenerio when there is no privateKey to export
	var privateKeyBytes []byte = nil
	var publicKey = p.publicKey

	if p.privateKey != nil {
		privateKeyBytes = x509.MarshalPKCS1PrivateKey(p.privateKey)
		publicKey = &p.privateKey.PublicKey
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)

	if err != nil {
		return nil, err
	}

	return &CryptographicKey{
		public:      publicKeyBytes,
		private:     privateKeyBytes,
		keyType:     "RSA",
		isSymmetric: false,
	}, nil
}

func RSA_CreateDeviceRandom(keylength_bits int) (*RsaCryptographicDevice, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keylength_bits)
	if err != nil {
		return nil, err
	}
	return &RsaCryptographicDevice{
		privateKey: privateKey,
	}, nil
}

// can accept nil as privateKey, then only pulic is parsed. If privateKey is supplied the other argument is ignored
func RSA_CreateDeviceFromPEM(privatePEM []byte, publicPEM []byte) (*RsaCryptographicDevice, error) {

	if privatePEM != nil { // in case there is privateKey, ignore public key PEM and derive it from private
		privateKeyBlock, _ := pem.Decode(privatePEM)
		if privateKeyBlock == nil {
			return nil, errors.New("Private key data is not a valid PEM format")
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			return nil, err
		}

		return &RsaCryptographicDevice{
			privateKey: privateKey,
			publicKey:  &privateKey.PublicKey,
		}, nil
	}

	// incase there is no private key, just parse public
	publicKeyBlock, _ := pem.Decode(publicPEM)
	if publicKeyBlock == nil {
		return nil, errors.New("Public ket data is not a valid PEM format")
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &RsaCryptographicDevice{
		publicKey:  publicKey.(*rsa.PublicKey),
		privateKey: nil,
	}, nil

}
