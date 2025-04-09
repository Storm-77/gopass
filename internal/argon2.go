package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	argon2_import "golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash = errors.New("the encoded argon2 hash is not in the correct format")
)

type Argon2Parameters struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

type Argon2KeyDerivationDevice struct {

	// "constructor" methods
	// CreateArgonDeviceSalt(params Argon2Parameters, salt []byte)
	// CreateArgonDeviceRandom(params Argon2Parameters)

	// methods
	// GenHash(passphrase string) ([]byte , error)
	// VerifyHash(passphrase string, reference []byte) (bool, error)
	// HashToString(key []byte) (string, error)
	// ParamsToString() (string, error)

	// private
	salt   []byte
	config Argon2Parameters
}

func GetSupportedArgonVersion() float64 {
	return argon2_import.Version
}

func (p *Argon2KeyDerivationDevice) GenHash(passphrase string) ([]byte, error) {

	params := &p.config
	// Pass the plaintext password, salt and parameters to the argon2.IDKey function. This will generate a hash of the password using the Argon2id variant.
	return argon2_import.IDKey([]byte(passphrase), p.salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength), nil
}

func (p *Argon2KeyDerivationDevice) HashToString(key []byte) (string, error) {

	b64Hash := base64.RawStdEncoding.EncodeToString(key)
	algorithm_params_string, err := p.ParamsToString()

	if err != nil {
		return "", err
	}

	// Return a string using the standard encoded hash representation.
	// format "algorithm:version$parameters$hash"
	encodedHash := fmt.Sprintf("%s:%d$%s$hash@%s",
		Algo_argon2, argon2_import.Version,
		algorithm_params_string,
		b64Hash,
	)

	return encodedHash, nil

}

// "m@memoy, i@Iterations, p@Parallelism, s@saltb64encoded"
func (p *Argon2KeyDerivationDevice) ParamsToString() (string, error) {

	if len(p.salt) == 0 {
		return "", errors.New("Couldnt export uncompleate parameters, missing salt")
	}

	b64Salt := base64.RawStdEncoding.EncodeToString(p.salt)
	params := p.config

	str := fmt.Sprintf(
		"m@%d,i@%d,p@%d,kl@%d,s@%s",
		params.Memory,
		params.Iterations,
		params.Parallelism,
		params.KeyLength,
		b64Salt,
	)

	return str, nil

}

// never errors out
func (p *Argon2KeyDerivationDevice) VerifyHash(passphrase string, reference []byte) (bool, error) {
	hash, _ := p.GenHash(passphrase)
	return bytes.Equal(hash, reference), nil // todo implement this
}

func CreateArgonDeviceRandom(params Argon2Parameters) (*Argon2KeyDerivationDevice, error) {
	salt, err := RandomBytes(params.SaltLength)
	if err != nil {
		return nil, err
	}

	return &Argon2KeyDerivationDevice{
		salt:   salt,
		config: params,
	}, nil
}

func CreateArgonDeviceSalt(params Argon2Parameters, salt []byte) (*Argon2KeyDerivationDevice, error) {

	if salt == nil || len(salt) == 0 {
		return nil, errors.New("Invalid salt parameter")
	}

	params.SaltLength = uint32(len(salt))

	return &Argon2KeyDerivationDevice{
		config: params,
		salt:   salt,
	}, nil
}

// returns ParametersStruct, salt, error
func ParseArgon2Parameters(encoded string) (*Argon2Parameters, []byte, error) {
	// mem, iter, Parallelism, salt
	var (
		memory      uint32
		iter        uint32
		parallelism uint8
		keyLength   uint32
		b64salt     string
	)

	items_parsed, err := fmt.Sscanf(encoded, "m@%d,i@%d,p@%d,kl@%d,s@%s", &memory, &iter, &parallelism, &keyLength, &b64salt)
	if err != nil {
		return nil, nil, err
	}
	if items_parsed != 5 {
		return nil, nil, errors.New("Couldnt parse argon2 parameters string. Invalid number of fields")
	}
	salt_bytes, err := base64.RawStdEncoding.DecodeString(b64salt)
	if err != nil {
		return nil, nil, err
	}

	salt_length := uint32(len(salt_bytes))

	return &Argon2Parameters{
			Memory:      memory,
			Iterations:  iter,
			Parallelism: parallelism,
			KeyLength:   keyLength,
			SaltLength:  salt_length,
		},
		salt_bytes,
		nil
}
