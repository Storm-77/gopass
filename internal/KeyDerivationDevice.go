package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type KeyDervationAlgorithm string

const (
	Algo_argon2 KeyDervationAlgorithm = "argon2"
)

type KeyDerivationDevice interface {
	GenHash(passphrase string) ([]byte, error)
	VerifyHash(passphrase string, reference []byte) (bool, error)
	HashToString(key []byte) (string, error)
	ParamsToString() (string, error)
}

var (
	ErrIncompatibleVersion   = errors.New("incompatible of argon2")
	ErrIncompatibleAlgorithm = errors.New("this is not a string representation of any supported algorithm hash")
)

// returns KDD, hashBytes, error
// hashBytes is null when no key is provided
func ParseHash(encodedHash string) (KeyDerivationDevice, []byte, error) {
	vals := strings.Split(encodedHash, "$")

	vlen := len(vals)

	// pass only when there are 2 or 3 parts in string
	if vlen != 3 && vlen != 2 {
		return nil, nil, ErrInvalidHash
	}

	// check if there is hash and parse it
	var hash_bytes []byte = nil
	if vlen == 3 {

		var b64hash string
		n, err := fmt.Sscanf(vals[2], "hash@%s", &b64hash)
		if err != nil {
			return nil, nil, err
		}
		if n == 1 { //we have hash
			hash_bytes, err = base64.RawStdEncoding.DecodeString(b64hash)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	// parse metadata
	metadata := strings.Split(vals[0], ":")

	if len(metadata) != 2 {
		return nil, nil, errors.New("Couldnt parse algorithm metadata, invalid format")
	}

	algorithm := metadata[0]
	version, err := strconv.ParseFloat(metadata[1], 32)

	if err != nil {
		return nil, nil, err
	}

	// parse core parameters with corresponding device
	switch algorithm {
	case string(Algo_argon2):

		if version != GetSupportedArgonVersion() {
			return nil, nil, ErrIncompatibleVersion
		}
		params, salt, err := ParseArgon2Parameters(vals[1])
		if err != nil {
			return nil, nil, err
		}
		device, err := CreateArgonDeviceSalt(*params, salt)
		if err != nil {
			return nil, nil, err
		}
		return device, hash_bytes, nil

	default:
		return nil, nil, ErrIncompatibleAlgorithm
	}

}
