package crypto

import (
	"bytes"
	"testing"

	"github.com/Storm-77/gopass/internal"
)

func TestEncryptingKeyWithKey(t *testing.T) {
	device, err := crypto.RSA_CreateDeviceRandom()
	if err != nil {
		t.Errorf("recieved error generating keys: %s", err.Error())
	}

	key, err := device.GetKey()
	if err != nil {
		t.Errorf("recieved error creating key struct: %s", err.Error())
	}

	device_aes, err := crypto.AES_CreateDeviceRandom()
	if err != nil {
		t.Errorf("recieved error generating keys: %s", err.Error())
	}

	encrypted_key, err := device_aes.Encrypt(key.GetPrivateRaw())
	if err != nil {
		t.Errorf("recieved error encrypting: %s", err.Error())
	}

	if bytes.Equal(encrypted_key, key.GetPrivateRaw()) {
		t.Error("Encryption didn't happen at all, result is the same as input")
	}

	decrypted, err := device_aes.Decrypt(encrypted_key)
	if err != nil {
		t.Errorf("recieved error decrypting payload: %s", err.Error())
	}

	if !bytes.Equal(decrypted, key.GetPrivateRaw()) {
		t.Error("invalid decryption, key isnt same after decryption as original")
	}

}
