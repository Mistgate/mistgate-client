package settings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const fileName = "settings.json"

type Settings struct {
	KillSwitch  string `json:"kill_switch"`
	LAN         bool   `json:"lan"`
	Protocol    string `json:"protocol"`
	Game        bool   `json:"game"`
	RouteMode   string `json:"route_mode"`
	RouteRegion string `json:"route_region"`
	// Connect when the service starts, to the target of the last connect call.
	Autoconnect bool   `json:"autoconnect"`
	LastServer  string `json:"last_server"`
	LastSub     string `json:"last_sub"`
}

type Store struct {
	mu      sync.RWMutex
	path    string
	value   Settings
	changes chan struct{}
}

var ErrBadParams = errors.New("bad settings parameters")

func Defaults() Settings {
	return Settings{KillSwitch: "while", LAN: true, Protocol: "auto", RouteMode: "all", RouteRegion: "auto"}
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("cannot create settings directory")
	}
	s := &Store{path: filepath.Join(dir, fileName), value: Defaults(), changes: make(chan struct{}, 1)}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, errors.New("cannot read settings")
	}
	var patch map[string]json.RawMessage
	if json.Unmarshal(data, &patch) != nil || patch == nil {
		return s, nil
	}
	value := Defaults()
	for key, raw := range patch {
		if !apply(&value, key, raw) {
			return s, nil
		}
	}
	s.value = value
	return s, nil
}

func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.value
}

func (s *Store) Set(patch map[string]json.RawMessage) (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value := s.value
	for key, raw := range patch {
		if !apply(&value, key, raw) {
			return s.value, ErrBadParams
		}
	}
	if value == s.value {
		return s.value, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return s.value, errors.New("cannot encode settings")
	}
	if err := save(s.path, data); err != nil {
		return s.value, err
	}
	s.value = value
	select {
	case s.changes <- struct{}{}:
	default:
	}
	return value, nil
}

func (s *Store) Changes() <-chan struct{} { return s.changes }

func apply(value *Settings, key string, raw json.RawMessage) bool {
	switch key {
	case "kill_switch":
		var v string
		if json.Unmarshal(raw, &v) != nil || v != "off" && v != "while" && v != "always" {
			return false
		}
		value.KillSwitch = v
	case "lan":
		var v bool
		if !strictBool(raw, &v) {
			return false
		}
		value.LAN = v
	case "protocol":
		var v string
		if json.Unmarshal(raw, &v) != nil || v != "auto" && v != "hysteria2" && v != "awg" {
			return false
		}
		value.Protocol = v
	case "game":
		var v bool
		if !strictBool(raw, &v) {
			return false
		}
		value.Game = v
	case "route_mode":
		var v string
		if json.Unmarshal(raw, &v) != nil || v != "all" && v != "smart" && v != "selected" {
			return false
		}
		value.RouteMode = v
	case "route_region":
		var v string
		if json.Unmarshal(raw, &v) != nil || v != "auto" && v != "none" && !validCountry(v) {
			return false
		}
		value.RouteRegion = v
	case "autoconnect":
		var v bool
		if !strictBool(raw, &v) {
			return false
		}
		value.Autoconnect = v
	case "last_server", "last_sub":
		var v string
		if json.Unmarshal(raw, &v) != nil || len(v) > 128 {
			return false
		}
		if key == "last_server" {
			value.LastServer = v
		} else {
			value.LastSub = v
		}
	default:
		return false
	}
	return true
}

func validCountry(value string) bool {
	return len(value) == 2 && value[0] >= 'a' && value[0] <= 'z' && value[1] >= 'a' && value[1] <= 'z'
}

func strictBool(raw json.RawMessage, value *bool) bool {
	text := strings.TrimSpace(string(raw))
	if text != "true" && text != "false" {
		return false
	}
	return json.Unmarshal(raw, value) == nil
}

func save(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".settings-*.tmp")
	if err != nil {
		return errors.New("cannot write settings")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err = temp.Write(data); err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("cannot write settings")
	}
	if err := os.Rename(tempPath, path); err != nil {
		return errors.New("cannot replace settings")
	}
	return nil
}
