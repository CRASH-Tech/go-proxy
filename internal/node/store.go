package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"goproxy/internal/config"
	"goproxy/internal/keys"
)

// Files kept in the data directory (GOPROXY_DATA_DIR). Both hold secrets
// (the key, peers' PSKs) and are written with mode 0600.
const (
	peersFile = "peers.json"
	keyFile   = "node.key"
)

// loadPeers reads the peers managed in the web UI; a missing file means none.
func loadPeers(dir string) ([]config.Peer, error) {
	b, err := os.ReadFile(filepath.Join(dir, peersFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var peers []config.Peer
	if err := json.Unmarshal(b, &peers); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, peersFile), err)
	}
	return peers, nil
}

func savePeers(dir string, peers []config.Peer) error {
	if peers == nil {
		peers = []config.Peer{}
	}
	b, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(dir, peersFile, append(b, '\n'))
}

// loadOrCreateKey returns the node's private key from the data directory,
// generating and saving one on first use.
func loadOrCreateKey(dir string) (key keys.PrivateKey, created bool, err error) {
	if dir == "" {
		return key, false, fmt.Errorf("no private key: set GOPROXY_PRIVATE_KEY or GOPROXY_DATA_DIR")
	}
	b, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err == nil {
		key, err = keys.ParsePrivateKey(strings.TrimSpace(string(b)))
		if err != nil {
			return key, false, fmt.Errorf("%s: %w", filepath.Join(dir, keyFile), err)
		}
		return key, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return key, false, err
	}
	if key, err = keys.GeneratePrivateKey(); err != nil {
		return key, false, err
	}
	return key, true, saveKey(dir, key)
}

func saveKey(dir string, key keys.PrivateKey) error {
	return writeFile(dir, keyFile, []byte(key.String()+"\n"))
}

// writeFile replaces dir/name atomically (write a temporary file, rename).
func writeFile(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}
