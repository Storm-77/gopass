package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	argon2_import "golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash           = errors.New("the encoded argon2 hash is not in the correct format")
	ErrIncompatibleVersion   = errors.New("incompatible version of argon2")
	ErrIncompatibleAlgorithm = errors.New("this is not a string representation of argon2 hash")
)

type Argon2DerivedKey struct {
	data          []byte
	device_config *Argon2Parameters
}

type Argon2Parameters struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32

	salt []byte
	// rewrite this to become sealed data struct
	// emlinate the possibility to change SaltLength from outside
}

type Argon2KeyDerivationDevice struct {
	config Argon2Parameters
}

func (p *Argon2KeyDerivationDevice) DeriveKey(passphrase string) (DerivedKey, error) {

	//parameters for argon 2 algorithm
	// if salt is present in the parameters struct use it, do not generate new
	params := &p.config

	salt, err := RandomBytes(params.SaltLength)
	if err != nil {
		return nil, err
	}

	// Pass the plaintext password, salt and parameters to the argon2.IDKey function. This will generate a hash of the password using the Argon2id variant.
	hash := argon2_import.IDKey([]byte(passphrase), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	params.salt = salt

	key_struct := Argon2DerivedKey{
		data:          hash,
		device_config: &p.config,
	}

	return key_struct, nil

}

// "m@memoy, i@Iterations, p@Parallelism, s@saltb64encoded"
func (p Argon2Parameters) ToStringRepresentation() (string, error) {

	if len(p.salt) == 0 {
		return "", errors.New("Couldnt export uncompleate parameters, missing salt")
	}

	b64Salt := base64.RawStdEncoding.EncodeToString(p.salt)

	str := fmt.Sprintf(
		"m@%d,i@%d,p@%d,kl@%d,s@%s",
		p.Memory,
		p.Iterations,
		p.Parallelism,
		p.KeyLength,
		b64Salt,
	)

	return str, nil

}

func (p Argon2DerivedKey) ToStringRepresentation() (string, error) {
	b64Hash := base64.RawStdEncoding.EncodeToString(p.data)
	algorithm_params_string, err := p.device_config.ToStringRepresentation()

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

func (p Argon2DerivedKey) GetBytes() []byte {
	return p.data
}

func (p *Argon2KeyDerivationDevice) VerifyPassphrase(passphrase string, reference string) (bool, error) {
	return true, errors.ErrUnsupported // todo implement this
}

func CreateArgonDerivationDevice(params Argon2Parameters) *Argon2KeyDerivationDevice {
	return &Argon2KeyDerivationDevice{
		config: params,
	}
}

//functrion to setup parameters for a platform

//function to load parameters from file

func parseArgon2Parameters(encoded string) (*Argon2Parameters, error) {
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
		return nil, err
	}
	if items_parsed != 5 {
		return nil, errors.New("Couldnt parse argon2 parameters string")
	}
	salt_bytes, err := base64.RawStdEncoding.DecodeString(b64salt)
	if err != nil {
		return nil, err
	}

	salt_length := uint32(len(salt_bytes))

	return &Argon2Parameters{
		Memory:      memory,
		Iterations:  iter,
		Parallelism: parallelism,
		KeyLength:   keyLength,
		SaltLength:  salt_length,
		salt:        salt_bytes,
	}, nil
}

// for now load config and sotore it in the same file
func ParseArgon2Hash(encodedHash string) (derived_key *Argon2DerivedKey, err error) {
	vals := strings.Split(encodedHash, "$")

	if len(vals) != 3 {
		return nil, ErrInvalidHash
	}

	{
		metadata := strings.Split(vals[0], ":")

		if len(metadata) != 2 {
			return nil, errors.New("Couldnt parse algorithm metadata, invalid format")
		}

		algorithm := metadata[0]
		version, err := strconv.ParseFloat(metadata[1], 32)

		if err != nil {
			return nil, err
		}

		switch algorithm {
		case string(Algo_argon2):

			if version != argon2_import.Version {
				return nil, ErrIncompatibleVersion
			}
			params, err := parseArgon2Parameters(vals[1])
			if err != nil {
				return nil, err
			}

			var b64hash string
			n, err := fmt.Sscanf(vals[2], "hash@%s", &b64hash)
			if err != nil {
				return nil, err
			}
			if n == 1 { //we have hash
				hash_bytes, err := base64.RawStdEncoding.DecodeString(b64hash)
				if err != nil {
					return nil, err
				}
				return &Argon2DerivedKey{
					data:          hash_bytes,
					device_config: params,
				}, nil

			}
			if n == 0 {
				//there is no hash, salt only
				return nil, nil
			}

		default:
			return nil, ErrIncompatibleAlgorithm

		}

	}

	return nil, nil
}
