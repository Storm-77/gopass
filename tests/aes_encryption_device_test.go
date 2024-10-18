package crypto

import (
	"bytes"
	"os"
	"testing"

	"github.com/Storm-77/gopass/internal"
)

func TestAesEncryptionDevice(t *testing.T) {

	text := TEST_PAYLOAD
	device, err := crypto.AES_CreateDeviceRandom()
	if err != nil {
		t.Errorf("recieved error generating keys: %s", err.Error())
	}

	encrypted, err := device.Encrypt(text)
	if err != nil {
		t.Errorf("recieved error encrypting: %s", err.Error())
	}

	if bytes.Equal(text, encrypted) {
		t.Error("Encryption didn't happen at all, result is the same as input")
	}
	decypted, err := device.Decrypt(encrypted)
	if err != nil {
		t.Errorf("recieved error decrypting payload: %s", err.Error())
	}

	if !bytes.Equal(decypted, text) {
		t.Errorf("Decrypted different text than original payload!\nExpected: %s\nRecieved: %s", text, decypted)
	}

	err = os.WriteFile("aes_test.enc", encrypted, 0644)
	if err != nil {
		t.Errorf("recieved error writing file to disk: %s", err.Error())
	}

	key, err := device.GetKey()

	if err != nil {
		t.Errorf("recieved error creating key struct: %s", err.Error())
	}

	secret, _ := key.ToPEM()

	err = os.WriteFile("aes_secret.pem", secret, 0644)
	if err != nil {
		t.Errorf("recieved error writing file to disk: %s", err.Error())
	}

}

func TestAesKeyImport(t *testing.T) {
	keyPem, err := os.ReadFile("aes_secret.pem")
	if err != nil {
		t.Errorf("recieved error reading file from disk: %s", err.Error())
	}

	device, err := crypto.AES_CreateDeviceFromPEM(keyPem)
	// import key from pem, decrypt and test if output is same as original

	encrypted, err := os.ReadFile("aes_test.enc")
	if err != nil {
		t.Errorf("recieved error reading file from disk: %s", err.Error())
	}
	decrypted, err := device.Decrypt(encrypted)
	if !bytes.Equal(decrypted, TEST_PAYLOAD) {
		t.Errorf("Decrypted different text than original payload!\nExpected: %s\nRecieved: %s", TEST_PAYLOAD, decrypted)
	}
}
