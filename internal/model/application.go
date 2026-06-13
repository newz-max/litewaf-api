package model

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	ApplicationModeMonitor = "monitor"
	ApplicationModeProtect = "protect"
	ApplicationModeOff     = "off"

	ListenerProtocolHTTP  = "http"
	ListenerProtocolHTTPS = "https"
)

var hostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

type Application struct {
	ID          int64                   `json:"id"`
	Name        string                  `json:"name"`
	Mode        string                  `json:"mode"`
	Enabled     bool                    `json:"enabled"`
	Description string                  `json:"description"`
	Hosts       []ApplicationHost       `json:"hosts"`
	Listeners   []ApplicationListener   `json:"listeners"`
	Upstreams   []ApplicationUpstream   `json:"upstreams"`
	ProxyConfig *ApplicationProxyConfig `json:"proxy_config,omitempty"`
	CreatedAt   time.Time               `json:"created_at"`
	UpdatedAt   time.Time               `json:"updated_at"`
}

type ApplicationHost struct {
	ID            int64  `json:"id"`
	ApplicationID int64  `json:"application_id"`
	Host          string `json:"host"`
	IsPrimary     bool   `json:"is_primary"`
}

type ApplicationListener struct {
	ID            int64  `json:"id"`
	ApplicationID int64  `json:"application_id"`
	Port          int    `json:"port"`
	Protocol      string `json:"protocol"`
	CertificateID int64  `json:"certificate_id,omitempty"`
	Enabled       bool   `json:"enabled"`
}

type ApplicationUpstream struct {
	ID            int64  `json:"id"`
	ApplicationID int64  `json:"application_id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	Weight        int    `json:"weight"`
	Enabled       bool   `json:"enabled"`
}

type ApplicationProxyConfig struct {
	Headers          []ApplicationProxyHeader `json:"headers,omitempty"`
	ConnectTimeout   string                   `json:"connect_timeout,omitempty"`
	ReadTimeout      string                   `json:"read_timeout,omitempty"`
	SendTimeout      string                   `json:"send_timeout,omitempty"`
	WebSocketEnabled bool                     `json:"websocket_enabled,omitempty"`
	PreserveHost     *bool                    `json:"preserve_host,omitempty"`
	ProxyBuffering   string                   `json:"proxy_buffering,omitempty"`
	RequestBuffering string                   `json:"request_buffering,omitempty"`
}

type ApplicationProxyHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Certificate struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Domains     []string  `json:"domains"`
	CertPEM     string    `json:"-"`
	KeyPEM      string    `json:"-"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func NormalizeApplication(app *Application) {
	app.Name = strings.TrimSpace(app.Name)
	app.Mode = strings.ToLower(strings.TrimSpace(app.Mode))
	if app.Mode == "" {
		app.Mode = ApplicationModeMonitor
	}
	app.Description = strings.TrimSpace(app.Description)
	for i := range app.Hosts {
		app.Hosts[i].Host = normalizeHost(app.Hosts[i].Host)
	}
	for i := range app.Listeners {
		app.Listeners[i].Protocol = strings.ToLower(strings.TrimSpace(app.Listeners[i].Protocol))
	}
	for i := range app.Upstreams {
		app.Upstreams[i].Name = strings.TrimSpace(app.Upstreams[i].Name)
		app.Upstreams[i].URL = strings.TrimSpace(app.Upstreams[i].URL)
		if app.Upstreams[i].Weight <= 0 {
			app.Upstreams[i].Weight = 1
		}
	}
	if app.ProxyConfig != nil {
		NormalizeApplicationProxyConfig(app.ProxyConfig)
		if isEmptyApplicationProxyConfig(*app.ProxyConfig) {
			app.ProxyConfig = nil
		}
	}
}

func ValidateApplication(app Application, certificateExists func(int64) bool) error {
	if strings.TrimSpace(app.Name) == "" {
		return errors.New("application name is required")
	}
	if !validApplicationMode(app.Mode) {
		return errors.New("application mode must be monitor, protect, or off")
	}
	if len(app.Hosts) == 0 {
		return errors.New("at least one application host is required")
	}
	seenHosts := map[string]bool{}
	primaryCount := 0
	for _, host := range app.Hosts {
		if !validHost(host.Host) {
			return fmt.Errorf("invalid application host %q", host.Host)
		}
		if seenHosts[host.Host] {
			return fmt.Errorf("duplicate application host %q", host.Host)
		}
		seenHosts[host.Host] = true
		if host.IsPrimary {
			primaryCount++
		}
	}
	if primaryCount > 1 {
		return errors.New("only one application host can be primary")
	}
	if len(app.Listeners) == 0 {
		return errors.New("at least one application listener is required")
	}
	seenListeners := map[string]bool{}
	for _, listener := range app.Listeners {
		if listener.Port <= 0 || listener.Port > 65535 {
			return fmt.Errorf("invalid listener port %d", listener.Port)
		}
		if listener.Protocol != ListenerProtocolHTTP && listener.Protocol != ListenerProtocolHTTPS {
			return errors.New("listener protocol must be http or https")
		}
		key := fmt.Sprintf("%d/%s", listener.Port, listener.Protocol)
		if seenListeners[key] {
			return fmt.Errorf("duplicate listener %s", key)
		}
		seenListeners[key] = true
		if listener.Enabled && listener.Protocol == ListenerProtocolHTTPS {
			if listener.CertificateID <= 0 {
				return fmt.Errorf("https listener %d requires a certificate", listener.Port)
			}
			if certificateExists != nil && !certificateExists(listener.CertificateID) {
				return fmt.Errorf("certificate %d does not exist", listener.CertificateID)
			}
		}
	}
	if len(app.Upstreams) == 0 {
		return errors.New("at least one application upstream is required")
	}
	enabledUpstreams := 0
	for _, upstream := range app.Upstreams {
		if upstream.URL == "" {
			return errors.New("upstream URL is required")
		}
		parsed, err := url.Parse(upstream.URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("invalid upstream URL %q", upstream.URL)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("upstream URL must use http or https")
		}
		if upstream.Enabled {
			enabledUpstreams++
		}
	}
	if enabledUpstreams == 0 {
		return errors.New("at least one upstream must be enabled")
	}
	if app.ProxyConfig != nil {
		if err := ValidateApplicationProxyConfig(*app.ProxyConfig); err != nil {
			return err
		}
	}
	return nil
}

var (
	proxyHeaderNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	proxyTimeoutPattern    = regexp.MustCompile(`^[1-9][0-9]{0,5}(ms|s|m|h)$`)
)

func NormalizeApplicationProxyConfig(config *ApplicationProxyConfig) {
	for i := range config.Headers {
		config.Headers[i].Name = strings.TrimSpace(config.Headers[i].Name)
		config.Headers[i].Value = strings.TrimSpace(config.Headers[i].Value)
	}
	filteredHeaders := make([]ApplicationProxyHeader, 0, len(config.Headers))
	for _, header := range config.Headers {
		if header.Name != "" || header.Value != "" {
			filteredHeaders = append(filteredHeaders, header)
		}
	}
	config.Headers = filteredHeaders
	config.ConnectTimeout = strings.ToLower(strings.TrimSpace(config.ConnectTimeout))
	config.ReadTimeout = strings.ToLower(strings.TrimSpace(config.ReadTimeout))
	config.SendTimeout = strings.ToLower(strings.TrimSpace(config.SendTimeout))
	config.ProxyBuffering = normalizeNginxOnOffDefault(config.ProxyBuffering)
	config.RequestBuffering = normalizeNginxOnOffDefault(config.RequestBuffering)
}

func ValidateApplicationProxyConfig(config ApplicationProxyConfig) error {
	for _, header := range config.Headers {
		if !proxyHeaderNamePattern.MatchString(header.Name) {
			return fmt.Errorf("invalid proxy header name %q", header.Name)
		}
		if strings.ContainsAny(header.Value, "\r\n") {
			return fmt.Errorf("proxy header %q contains an invalid value", header.Name)
		}
	}
	for name, value := range map[string]string{
		"proxy connect timeout": config.ConnectTimeout,
		"proxy read timeout":    config.ReadTimeout,
		"proxy send timeout":    config.SendTimeout,
	} {
		if value != "" && !proxyTimeoutPattern.MatchString(value) {
			return fmt.Errorf("%s must use nginx time syntax such as 30s, 5m, or 500ms", name)
		}
	}
	if !validNginxOnOffDefault(config.ProxyBuffering) {
		return errors.New("proxy buffering must be default, on, or off")
	}
	if !validNginxOnOffDefault(config.RequestBuffering) {
		return errors.New("proxy request buffering must be default, on, or off")
	}
	return nil
}

func isEmptyApplicationProxyConfig(config ApplicationProxyConfig) bool {
	return len(config.Headers) == 0 &&
		config.ConnectTimeout == "" &&
		config.ReadTimeout == "" &&
		config.SendTimeout == "" &&
		!config.WebSocketEnabled &&
		config.PreserveHost == nil &&
		config.ProxyBuffering == "" &&
		config.RequestBuffering == ""
}

func normalizeNginxOnOffDefault(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "true", "1", "yes":
		return "on"
	case "off", "false", "0", "no":
		return "off"
	case "default", "":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func validNginxOnOffDefault(value string) bool {
	return value == "" || value == "on" || value == "off"
}

func ParseCertificate(name, certPEM, keyPEM string) (Certificate, error) {
	certBlock, _ := pem.Decode([]byte(strings.TrimSpace(certPEM)))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return Certificate{}, errors.New("certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return Certificate{}, fmt.Errorf("parse certificate: %w", err)
	}
	keyBlock, _ := pem.Decode([]byte(strings.TrimSpace(keyPEM)))
	if keyBlock == nil {
		return Certificate{}, errors.New("private key PEM is invalid")
	}
	privateKey, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return Certificate{}, err
	}
	if !publicKeysEqual(cert.PublicKey, publicKey(privateKey)) {
		return Certificate{}, errors.New("certificate and private key do not match")
	}
	sum := sha256.Sum256(cert.Raw)
	return Certificate{
		Name:        strings.TrimSpace(name),
		Domains:     certificateDomains(cert),
		CertPEM:     strings.TrimSpace(certPEM),
		KeyPEM:      strings.TrimSpace(keyPEM),
		NotBefore:   cert.NotBefore.UTC(),
		NotAfter:    cert.NotAfter.UTC(),
		Fingerprint: strings.ToLower(hex.EncodeToString(sum[:])),
	}, nil
}

func ValidateCertificate(cert Certificate) error {
	if strings.TrimSpace(cert.Name) == "" {
		return errors.New("certificate name is required")
	}
	if strings.TrimSpace(cert.CertPEM) == "" {
		return errors.New("certificate PEM is required")
	}
	if strings.TrimSpace(cert.KeyPEM) == "" {
		return errors.New("private key PEM is required")
	}
	if len(cert.Domains) == 0 {
		return errors.New("certificate must contain at least one DNS name, IP address, or common name")
	}
	if cert.Fingerprint == "" || cert.NotAfter.IsZero() {
		return errors.New("certificate metadata is incomplete")
	}
	return nil
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 || strings.Contains(host, ":") || strings.Contains(host, "/") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return hostPattern.MatchString(host)
}

func validApplicationMode(mode string) bool {
	return mode == ApplicationModeMonitor || mode == ApplicationModeProtect || mode == ApplicationModeOff
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported or invalid private key")
}

func publicKey(privateKey crypto.PrivateKey) crypto.PublicKey {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	case ed25519.PrivateKey:
		return key.Public()
	default:
		return nil
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	ader, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bder, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return string(ader) == string(bder)
}

func certificateDomains(cert *x509.Certificate) []string {
	seen := map[string]bool{}
	for _, name := range cert.DNSNames {
		seen[normalizeHost(name)] = true
	}
	for _, ip := range cert.IPAddresses {
		seen[ip.String()] = true
	}
	if cert.Subject.CommonName != "" {
		seen[normalizeHost(cert.Subject.CommonName)] = true
	}
	items := make([]string, 0, len(seen))
	for item := range seen {
		if item != "" {
			items = append(items, item)
		}
	}
	sort.Strings(items)
	return items
}
