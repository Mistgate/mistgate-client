package proxy

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
)

const passwordFile = "proxy.json"

// No 0/O and 1/l/I: the password is read off a screen and typed into a TV.
const passwordAlphabet = "23456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"

const passwordLength = 16

func newPassword() (string, error) {
	limit := big.NewInt(int64(len(passwordAlphabet)))
	out := make([]byte, passwordLength)
	for i := range out {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		out[i] = passwordAlphabet[n.Int64()]
	}
	return string(out), nil
}

func validPassword(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// readPassword is "" when there is no usable file; the next enable makes a new password.
func readPassword(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, passwordFile))
	if err != nil {
		return ""
	}
	var stored struct {
		Password string `json:"password"`
	}
	if json.Unmarshal(data, &stored) != nil || !validPassword(stored.Password) {
		return ""
	}
	return stored.Password
}

// writePassword keeps the password next to the settings, in the data directory whose access the subscription store
// has already narrowed to SYSTEM and administrators; it is not in settings.json because that goes to the window in
// events. The file is replaced whole, so a crash leaves the old or the new one.
func writePassword(dir, password string) error {
	data, err := json.Marshal(struct {
		Password string `json:"password"`
	}{password})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create the data directory")
	}
	temp, err := os.CreateTemp(dir, ".proxy-*.tmp")
	if err != nil {
		return errors.New("cannot write the proxy file")
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("cannot write the proxy file")
	}
	if os.Rename(temp.Name(), filepath.Join(dir, passwordFile)) != nil {
		return errors.New("cannot replace the proxy file")
	}
	return nil
}
