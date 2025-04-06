package crypto

type KeyDervationAlgorithm string

const (
	Algo_argon2 KeyDervationAlgorithm = "argon2"
)

type DerivedKey interface {
	ToStringRepresentation() (string, error)
	GetBytes() []byte
}

type KeyDerivationDeviceParams interface {
	ToStringRepresentation() (string, error)
}

type KeyDerivationDevice interface {
	DeriveKey(passphrase string) (DerivedKey, error)
	VerifyPassphrase(passphrase string, reference string) (bool, error)
	Configuration() (KeyDerivationDeviceParams)
}
