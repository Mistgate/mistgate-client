package geo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

type SiteSet struct {
	domains map[string]struct{}
}

func (s *SiteSet) Match(name string) bool {
	if s == nil {
		return false
	}
	name, ok := normalizeSiteDomain(name)
	if !ok {
		return false
	}
	for start := 0; ; {
		if _, exists := s.domains[name[start:]]; exists {
			return true
		}
		dot := strings.IndexByte(name[start:], '.')
		if dot < 0 {
			return false
		}
		start += dot + 1
	}
}

func (s *SiteSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.domains)
}

func (s *SiteSet) add(domain string) {
	if s.domains == nil {
		s.domains = make(map[string]struct{})
	}
	s.domains[domain] = struct{}{}
}

func parseSites(data []byte) (*SiteSet, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxFileBytes)
	set := &SiteSet{domains: make(map[string]struct{})}
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.IndexFunc(line, unicode.IsSpace) >= 0 {
			continue
		}
		switch {
		case strings.HasPrefix(line, "+.") || strings.HasPrefix(line, "*."):
			line = line[2:]
		case strings.HasPrefix(line, "."):
			line = line[1:]
		case strings.HasPrefix(line, "+") || strings.HasPrefix(line, "*"):
			continue
		}
		if domain, ok := normalizeSiteDomain(line); ok {
			set.add(domain)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("site list is too large or unreadable")
	}
	if set.Len() == 0 {
		return nil, errors.New("site list has no valid domains")
	}
	return set, nil
}

func normalizeSiteDomain(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" || len(value) > 253 || strings.ContainsAny(value, " /:\\?#@") {
		return "", false
	}
	// Labels are walked in place: this runs for every DNS question, and strings.Split allocates.
	for start, i := 0, 0; i <= len(value); i++ {
		if i < len(value) && value[i] != '.' {
			continue
		}
		label := value[start:i]
		start = i + 1
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if r == '-' || r >= '0' && r <= '9' || unicode.IsLetter(r) {
				continue
			}
			return "", false
		}
	}
	return value, true
}

// NormalizeSite is the check every site entry passes: a host name, or an https URL of one.
func NormalizeSite(value string) (string, bool) { return normalizeUserSite(value) }

func (s *Store) Sites(collection string) (*SiteSet, bool) {
	if s == nil {
		return nil, false
	}
	path, _, ok := siteCachePath(s.dir, collection)
	if !ok {
		return nil, false
	}
	s.mu.Lock()
	if !s.siteLoaded[collection] {
		s.siteLoaded[collection] = true
		if info, err := os.Stat(path); err == nil && info.Size() <= maxFileBytes {
			if data, err := os.ReadFile(path); err == nil {
				if set, parseErr := parseSites(data); parseErr == nil {
					s.siteSets[collection] = set
				}
			}
		}
	}
	set := s.siteSets[collection]
	info, statErr := os.Stat(path)
	stale := statErr != nil || time.Since(info.ModTime()) >= maxAge
	if stale && !s.siteRefreshing[collection] {
		s.siteRefreshing[collection] = true
		go s.refreshSites(collection, path)
	}
	s.mu.Unlock()
	return set, set != nil
}

func (s *Store) siteSet(collection string) (*SiteSet, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.siteSets[collection]
	return set, set != nil
}

func (s *Store) sitePath(collection string) string {
	path, _, _ := siteCachePath(s.dir, collection)
	return path
}

func siteCachePath(dir, collection string) (string, string, bool) {
	kind, value, ok := strings.Cut(collection, ":")
	if !ok {
		return "", "", false
	}
	switch kind {
	case "geosite":
		if !validGeoSiteName(value) {
			return "", "", false
		}
		return filepath.Join(dir, "site-"+value+".list"), value, true
	case "list":
		if !validSiteURL(value) {
			return "", "", false
		}
		sum := sha256.Sum256([]byte(value))
		return filepath.Join(dir, "list-"+hex.EncodeToString(sum[:8])+".list"), value, true
	default:
		return "", "", false
	}
}

func validGeoSiteName(name string) bool {
	if len(name) < 1 || len(name) > 48 {
		return false
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '!' || r == '@' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validSiteURL(value string) bool {
	if len(value) > 512 {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
}

func (s *Store) refreshSites(collection, path string) {
	defer func() {
		s.mu.Lock()
		s.siteRefreshing[collection] = false
		s.mu.Unlock()
	}()
	data, set, err := s.fetchSites(collection)
	if err != nil || writeAtomic(path, data) != nil {
		return
	}
	s.mu.Lock()
	s.siteSets[collection] = set
	s.siteLoaded[collection] = true
	s.mu.Unlock()
	s.rebuildSiteRules()
	s.signalChange()
}

func (s *Store) fetchSites(collection string) ([]byte, *SiteSet, error) {
	_, value, ok := siteCachePath(s.dir, collection)
	if !ok {
		return nil, nil, errors.New("invalid site collection")
	}
	urls := []string{value}
	if strings.HasPrefix(collection, "geosite:") {
		urls = []string{fmt.Sprintf(s.sitePrimaryURL, value), fmt.Sprintf(s.siteFallbackURL, value)}
	}
	for _, rawURL := range urls {
		data, err := s.fetchURL(rawURL)
		if err != nil {
			continue
		}
		set, err := parseSites(data)
		if err == nil {
			return data, set, nil
		}
	}
	return nil, nil, errors.New("site collection unavailable")
}

func (s *Store) fetchURL(rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("invalid site URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("invalid site URL")
	}
	request.Header.Set("User-Agent", "Mistgate/0.0.1")
	client := *s.client
	client.Timeout = fetchTimeout
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || req.URL.User != nil || len(via) >= 5 {
			return errors.New("invalid site redirect")
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("site request failed")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxFileBytes+1))
	if err != nil || len(data) > maxFileBytes {
		return nil, errors.New("site list is too large or unreadable")
	}
	return data, nil
}
