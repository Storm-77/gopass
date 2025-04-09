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
	device, err := crypto.CreateArgonDeviceRandom(config)

	if err != nil {
		t.Errorf("WTF: %s", err.Error())
	}

	key, _ := device.GenHash(TEST_ARGON2_PASSPHRASE)

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
	device, err := crypto.CreateArgonDeviceRandom(config)

	if err != nil {
		t.Errorf("WTF: %s", err.Error())
	}

	key, _ := device.GenHash(TEST_ARGON2_PASSPHRASE)
	_, err = device.HashToString(key)

	if err != nil {
		t.Errorf("received error generating string representation: %s", err.Error())
	}

}

func TestArgonStringRepresentationParsing(t *testing.T) {
	config := TEST_ARGON2_PARAMETERS
	device, err := crypto.CreateArgonDeviceRandom(config)

	if err != nil {
		t.Errorf("WTF: %s", err.Error())
	}

	key_bytes, _ := device.GenHash(TEST_ARGON2_PASSPHRASE)
	str, err := device.HashToString(key_bytes)

	if err != nil {
		t.Errorf("received error generating string representation: %s", err.Error())
	}

	device_2, key, err := crypto.ParseHash(str)

	if err != nil {
		t.Errorf("received error parsing string representation: %s", err.Error())
	}

	if key == nil {
		t.Error("nil returned, key not parsed")
	}

	if device_2 == nil {
		t.Errorf("nil returned, params not parsed")
	}

	t.Log(device_2.HashToString(key_bytes))
}

func TestArgonPartialStringRepresentationParsing(t *testing.T) {

	config := TEST_ARGON2_PARAMETERS
	device, err := crypto.CreateArgonDeviceRandom(config)

	if err != nil {
		t.Errorf("WTF: %s", err.Error())
	}

	key_bytes, _ := device.GenHash(TEST_ARGON2_PASSPHRASE)
	pstr, _ := device.ParamsToString()

	// validate if we can go from partial string to working device

	t.Log(pstr)

	str, err := device.HashToString(key_bytes)

	if err != nil {
		t.Errorf("received error generating string representation: %s", err.Error())
	}

	t.Log(str)
	device_2, key, err := crypto.ParseHash(str)
	if err != nil {
		t.Errorf("received error parsing string representation: %s", err.Error())
	}

	if key == nil {
		t.Error("nil returned, key not parsed")
	}

	if device_2 == nil {
		t.Error("nil returned, params not parsed")
	}

}

func TestArgonPartialStringRepresentation__OK(t *testing.T) {
	str := "argon2:19$m@65536,i@3,p@2,kl@128,s@0F5lMVL8GW86aNYtkUu+VCGqAZTbY+wS3dmD++cgo88"
	device, key, err := crypto.ParseHash(str)

	if key != nil {
		t.Error("not nil key returned when no key provided")
	}

	if err != nil {
		t.Errorf("received error parsing string representation: %s", err.Error())
	}

	if device == nil {
		t.Error("nil returned, params not parsed")
	}

	hash, _ := device.GenHash("HEllo there")
	str_2, err := device.HashToString(hash)

	if err != nil {
		t.Errorf("WTF: %s", err.Error())
	}

	t.Logf("Hash string: %s", str_2)
}

func TestArgonPartialStringRepresentation__ErrorHandling(t *testing.T) {
	str := "argon2:19$m@65536,i@3,p@2,kl@128"
	device, key, err := crypto.ParseHash(str)

	if key != nil {
		t.Error("not nil key returned when no key provided")
	}

	if err == nil {
		t.Error("received no error after invalid input")
	}

	if device != nil {
		t.Error("value returned, expected nil")
	}
}
