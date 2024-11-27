package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/pem"
	"errors"
)

type AesCryptographicDevice struct {
	key []byte
}

// EncryptAES encrypts plaintext using AES with the provided key
func (p AesCryptographicDevice) Encrypt(payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, payload, nil)
	return ciphertext, nil
}

// DecryptAES decrypts ciphertext using AES with the provided key
func (p AesCryptographicDevice) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (p *AesCryptographicDevice) GetKey() (*CryptographicKey, error) {

	return &CryptographicKey{
		public:      nil,
		private:     p.key,
		keyType:     "AES",
		isSymmetric: true,
	}, nil
}

func AES_CreateDeviceRandom() (*AesCryptographicDevice, error) {
	// Generate a random AES key (32 bytes for AES-256)
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		err2 := errors.New("Error generating AES key")
		return nil, errors.Join(err2, err)
	}

	return &AesCryptographicDevice{
		key: aesKey,
	}, nil

}

func AES_CreateDeviceFromPEM(pemString []byte) (*AesCryptographicDevice, error) {
	key, _ := pem.Decode(pemString)

	return &AesCryptographicDevice{
		key: key.Bytes,
	}, nil

}
