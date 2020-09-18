package client

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"

	"github.com/golang/glog"
	"golang.org/x/crypto/ssh"
)

// ConfigLoader defines configurations about how to load SSH client config.
type ConfigLoader struct {
	UserName       string
	HomeDir        string
	PrivateKeyFile string
	KnownHostsFile string
}

// Load loads SSH client config.
func (l ConfigLoader) Load() (*ssh.ClientConfig, error) {
	userName, homeDir := l.UserName, l.HomeDir
	if userName == "" {
		userName = os.Getenv("USER")
	}
	if homeDir == "" {
		homeDir = os.Getenv("HOME")
	}
	if userName == "" || homeDir == "" {
		currentUser, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("no current user: %w", err)
		}
		if userName == "" {
			userName = currentUser.Username
		}
		if homeDir == "" {
			homeDir = currentUser.HomeDir
		}
	}

	privateKeyFile := l.PrivateKeyFile
	if privateKeyFile == "" {
		privateKeyFile = filepath.Join(homeDir, ".ssh", "id_rsa")
	}

	knownHostsFile := l.KnownHostsFile
	if knownHostsFile == "" {
		knownHostsFile = filepath.Join(homeDir, ".ssh", "known_hosts")
	}

	keyData, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read key %q error: %w", privateKeyFile, err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse key %q error: %w", privateKeyFile, err)
	}
	return &ssh.ClientConfig{
		User:            userName,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: KnownHostsKeyCallback(knownHostsFile),
	}, nil
}

// LoadAndDial loads the config and connect to the server.
func (l ConfigLoader) LoadAndDial(serverAddr string) (*ssh.Client, error) {
	config, err := l.Load()
	if err != nil {
		return nil, err
	}
	return ssh.Dial("tcp", serverAddr, config)
}

// DefaultConfig loads SSH client config from current user environment.
func DefaultConfig() (*ssh.ClientConfig, error) {
	var loader ConfigLoader
	return loader.Load()
}

// KnownHosts contains valid known hosts.
type KnownHosts struct {
	Keys  map[string]ssh.PublicKey
	Hosts map[string]map[string]ssh.PublicKey
}

// LoadKnownHostsFileIfChanged loads known_hosts file if it has been updated.
func LoadKnownHostsFileIfChanged(knownHostsFile string, knownHosts *KnownHosts, info os.FileInfo) (*KnownHosts, os.FileInfo, error) {
	newInfo, err := os.Lstat(knownHostsFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &KnownHosts{}, nil, nil
		}
		return knownHosts, info, err
	}
	if knownHosts != nil && info != nil {
		if newInfo.ModTime() == info.ModTime() && newInfo.Size() == info.Size() {
			return knownHosts, newInfo, nil
		}
	}

	data, err := ioutil.ReadFile(knownHostsFile)
	if err != nil {
		return knownHosts, info, err
	}
	newHosts := &KnownHosts{
		Keys:  make(map[string]ssh.PublicKey),
		Hosts: make(map[string]map[string]ssh.PublicKey),
	}
	for len(data) > 0 {
		marker, hosts, pubKey, _, rest, err := ssh.ParseKnownHosts(data)
		if err != nil {
			return knownHosts, info, err
		}
		data = rest
		if marker == "revoked" {
			continue
		}
		pubKeyID := string(ssh.MarshalAuthorizedKey(pubKey))
		newHosts.Keys[pubKeyID] = pubKey
		for _, host := range hosts {
			keys := newHosts.Hosts[host]
			if keys == nil {
				keys = make(map[string]ssh.PublicKey)
				newHosts.Hosts[host] = keys
			}
			keys[pubKeyID] = pubKey
		}
	}
	return newHosts, newInfo, nil
}

func loadKnownHosts(knownHostsFile string, knownHosts *KnownHosts, info os.FileInfo) (*KnownHosts, os.FileInfo) {
	newHosts, newInfo, err := LoadKnownHostsFileIfChanged(knownHostsFile, knownHosts, info)
	if err != nil {
		glog.Errorf("Load %q error: %v", knownHostsFile, err)
	}
	return newHosts, newInfo
}

// KnownHostsKeyCallback verifies host key using known_hosts file.
func KnownHostsKeyCallback(knownHostsFile string) ssh.HostKeyCallback {
	knownHosts, fileInfo := loadKnownHosts(knownHostsFile, &KnownHosts{}, nil)
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		knownHosts, fileInfo = loadKnownHosts(knownHostsFile, knownHosts, fileInfo)
		keyID := string(ssh.MarshalAuthorizedKey(key))
		if knownHosts.Keys[keyID] != nil {
			return nil
		}
		return fmt.Errorf("unknown host key for %q (%s)", hostname, remote)
	}
}
