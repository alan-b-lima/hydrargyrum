package hg

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

func KeyGen(algo string) (crypto.PrivateKey, crypto.PublicKey, error) {
	var (
		priv crypto.PrivateKey
		pub  crypto.PublicKey
	)

	switch algo {
	case "rsa", "rsa2048":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("hg: %w", err)
		}

		priv, pub = key, key.PublicKey

	case "rsa3072":
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, nil, fmt.Errorf("hg: %w", err)
		}

		priv, pub = key, key.PublicKey

	case "rsa4096":
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, fmt.Errorf("hg: %w", err)
		}

		priv, pub = key, key.PublicKey

	case "ed25519":
		edpub, edpriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("hg: %w", err)
		}

		pub, priv = edpub, edpriv

	default:
		return nil, nil, fmt.Errorf("hg: unknown key algorithm %+q", algo)
	}

	return priv, pub, nil
}

func marshalPublicKey(name string, key crypto.PublicKey) error {
	sshkey, err := ssh.NewPublicKey(key)
	if err != nil {
		return err
	}

	bytes := ssh.MarshalAuthorizedKey(sshkey)

	file, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := file.Chmod(0o600); err != nil {
		return err
	}

	if _, err := file.Write(bytes); err != nil {
		return err
	}

	return nil
}

func marshalPrivateKey(name string, key crypto.PrivateKey) error {
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return err
	}

	file, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := file.Chmod(0o600); err != nil {
		return err
	}

	if err := pem.Encode(file, block); err != nil {
		return err
	}

	return nil
}
