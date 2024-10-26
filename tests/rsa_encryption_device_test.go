package crypto

import (
	"bytes"
	"github.com/Storm-77/gopass/internal"
	"os"
	"testing"
)

var (
	TEST_PAYLOAD        = []byte("TESTING IT")
	TEST_RSA_KEY_LENGTH = 2048
)

func ENCRYPT_DECRYPT_COMPARE(t *testing.T, device crypto.CryptographicDevice, payload string) {

	text := []byte(payload)

	encrypted, err := device.Encrypt(text)
	if err != nil {
		t.Errorf("recieved error encrypting payload: %s", err.Error())
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
}

func TestRsaEncryptionDevice(t *testing.T) {

	device, err := crypto.RSA_CreateDeviceRandom(TEST_RSA_KEY_LENGTH)
	if err != nil {
		t.Errorf("recieved error generating keys: %s", err.Error())
	}

	ENCRYPT_DECRYPT_COMPARE(t, device, "WHATEVER IM TESTIMG")

}

func TestRsaPemKey_Export(t *testing.T) {
	device, err := crypto.RSA_CreateDeviceRandom(TEST_RSA_KEY_LENGTH)
	if err != nil {
		t.Errorf("recieved error generating keys: %s", err.Error())
	}
	t.Log("Random keys generated with no errors")

	key, err := device.GetKey()
	if err != nil {
		t.Errorf("recieved error creating key struct: %s", err.Error())
	}

	private, public := key.ToPEM()

	err = os.WriteFile("private.pem", private, 0644)
	if err != nil {
		t.Errorf("recieved error writing file to disk: %s", err.Error())
	}

	err = os.WriteFile("public.pem", public, 0644)
	if err != nil {
		t.Errorf("recieved error writing file to disk: %s", err.Error())
	}

	encrypted, _ := device.Encrypt(TEST_PAYLOAD)

	err = os.WriteFile("encrypted.enc", encrypted, 0644)
	if err != nil {
		t.Errorf("recieved error encrypting file: %s", err.Error())
	}

}

func TestRsaPemPrivateKey_Import(t *testing.T) {
	// generated random keys and saved in files

	// implement RSA REM format key import

	privateKeyPEM, err := os.ReadFile("private.pem")
	if err != nil {
		t.Errorf("recieved error reading file from disk: %s", err.Error())
	}

	encrypted, err := os.ReadFile("encrypted.enc")
	if err != nil {
		t.Errorf("recieved error reading file from disk: %s", err.Error())
	}

	device, err := crypto.RSA_CreateDeviceFromPEM(privateKeyPEM, nil)

	decypted, err := device.Decrypt(encrypted)
	if err != nil {
		t.Errorf("recieved error decrypting payload: %s", err.Error())
	}

	if !bytes.Equal(decypted, TEST_PAYLOAD) {
		t.Errorf("Decrypted different text than original payload!\nExpected: %s\nRecieved: %s", TEST_PAYLOAD, decypted)
	}

	//test is keys are the same
	key, err := device.GetKey()
	if err != nil {
		t.Errorf("error in ecoding function: %s", err.Error())
	}

	priv, pub := key.ToPEM()
	if !bytes.Equal(priv, privateKeyPEM) {
		t.Errorf("private key mismatch, parsed different that file contains:\nparsed:%s\nfile:\n%s", priv, privateKeyPEM)
	}
	t.Log("Imported private key pem matches file key pem")

	publicKeyPEM, err := os.ReadFile("public.pem")
	if err != nil {
		t.Errorf("recieved error reading file from disk: %s", err.Error())
	}

	if !bytes.Equal(pub, publicKeyPEM) {
		t.Errorf("public key mismatch, parsed different that file contains:\nparsed:\n%s\nfile:\n%s", pub, publicKeyPEM)
	}
	t.Log("Imported public key pem matches file key pem")

}
func TestRsaPemPublicKey_Import(t *testing.T) {

	publicKeyPEM, err := os.ReadFile("public.pem")
	if err != nil {
		t.Errorf("recieved error reading file from disk: %s", err.Error())
	}

	device, err := crypto.RSA_CreateDeviceFromPEM(nil, publicKeyPEM)
	encrypted, _ := device.Encrypt(TEST_PAYLOAD)

	err = os.WriteFile("encrypted2.enc", encrypted, 0644)
	if err != nil {
		t.Errorf("recieved error encrypting file: %s", err.Error())
	}

	encrypted_file, err := os.ReadFile("encrypted.enc")
	if err != nil {
		t.Errorf("recieved error reading file from disk: %s", err.Error())
	}
	if bytes.Equal(encrypted_file, encrypted) {
		t.Error("Encrypting the same payload twice gives same result, not enouch entrophy")
	}
}
func TestDecrypting_message_encrypted_with_imported_key(t *testing.T) {

	privateKeyPEM, err := os.ReadFile("private.pem")
	if err != nil {
		t.Errorf("recieved error reading file from disk: %s", err.Error())
	}

	encrypted, err := os.ReadFile("encrypted2.enc")
	if err != nil {
		t.Errorf("recieved error reading file from disk: %s", err.Error())
	}

	device, err := crypto.RSA_CreateDeviceFromPEM(privateKeyPEM, nil)

	decypted, err := device.Decrypt(encrypted)
	if err != nil {
		t.Errorf("recieved error decrypting payload: %s", err.Error())
	}

	if !bytes.Equal(decypted, TEST_PAYLOAD) {
		t.Errorf("Decrypted different text than original payload!\nExpected: %s\nRecieved: %s", TEST_PAYLOAD, decypted)
	}
}
