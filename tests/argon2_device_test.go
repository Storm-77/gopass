package crypto

import (
	"github.com/Storm-77/gopass/internal"
	"testing"
)

var TEST_ARGON2_PARAMETERS = crypto.Argon2Parameters{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  32,
	KeyLength:   128,
}

const TEST_ARGON2_PASSPHRASE = "test123"

func TestArgonDerivation(t *testing.T) {
	config := TEST_ARGON2_PARAMETERS
	device := crypto.CreateArgonDerivationDevice(config)

	key_obj, err := device.DeriveKey(TEST_ARGON2_PASSPHRASE)
	key := key_obj.GetBytes()

	if err != nil {
		t.Errorf("received error generating key: %s", err.Error())
	}

	if len(key) == 0 {
		t.Error("No key received, length=0")
	}

	t.Logf("\nKey: %x\nKeyLen: %d (%d)\n", key, len(key), len(key)*8)

}

func TestArgonStringRepresentationEncoding(t *testing.T) {
	config := TEST_ARGON2_PARAMETERS
	device := crypto.CreateArgonDerivationDevice(config)
	key_obj, err := device.DeriveKey(TEST_ARGON2_PASSPHRASE)
	_, err = key_obj.ToStringRepresentation()

	if err != nil {
		t.Errorf("received error generating string representation: %s", err.Error())
	}

}

func TestArgonStringRepresentationParsing(t *testing.T) {
	config := TEST_ARGON2_PARAMETERS
	device := crypto.CreateArgonDerivationDevice(config)
	key_obj, err := device.DeriveKey(TEST_ARGON2_PASSPHRASE)
	str, err := key_obj.ToStringRepresentation()

	if err != nil {
		t.Errorf("received error generating string representation: %s", err.Error())
	}

	key, err := crypto.ParseArgon2Hash(str)
	if err != nil {
		t.Errorf("received error parsing string representation: %s", err.Error())
	}

	if key == nil {
		t.Error("nil returned, string not parsed")
	}

}
