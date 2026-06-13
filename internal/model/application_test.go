package model

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseCertificateValidatesAndRedactsKey(t *testing.T) {
	certPEM, keyPEM := testCertificatePEM(t, "app.example.test")
	cert, err := ParseCertificate("App cert", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if cert.Fingerprint == "" || cert.NotAfter.IsZero() {
		t.Fatalf("expected certificate metadata: %+v", cert)
	}
	if len(cert.Domains) != 1 || cert.Domains[0] != "app.example.test" {
		t.Fatalf("unexpected domains: %+v", cert.Domains)
	}
	if strings.Contains(cert.Fingerprint, "PRIVATE KEY") {
		t.Fatalf("fingerprint leaked key material: %s", cert.Fingerprint)
	}
}

func TestParseCertificateRejectsMismatchedKey(t *testing.T) {
	certPEM, _ := testCertificatePEM(t, "app.example.test")
	_, otherKey := testCertificatePEM(t, "other.example.test")
	if _, err := ParseCertificate("bad", certPEM, otherKey); err == nil {
		t.Fatal("expected mismatched key to fail")
	}
}

func TestValidateApplicationRequiresCertificateForHTTPS(t *testing.T) {
	app := Application{
		Name:    "App",
		Mode:    ApplicationModeProtect,
		Enabled: true,
		Hosts: []ApplicationHost{
			{Host: "app.example.test", IsPrimary: true},
		},
		Listeners: []ApplicationListener{
			{Port: 443, Protocol: ListenerProtocolHTTPS, Enabled: true},
		},
		Upstreams: []ApplicationUpstream{
			{URL: "http://127.0.0.1:9000", Weight: 1, Enabled: true},
		},
	}
	if err := ValidateApplication(app, nil); err == nil {
		t.Fatal("expected https listener without certificate to fail")
	}
	app.Listeners[0].CertificateID = 1
	if err := ValidateApplication(app, func(id int64) bool { return id == 1 }); err != nil {
		t.Fatalf("expected valid application: %v", err)
	}
}

func TestNormalizeApplicationBackfillsSingleUpstreamName(t *testing.T) {
	app := Application{
		Name:    "App",
		Mode:    ApplicationModeProtect,
		Enabled: true,
		Hosts:   []ApplicationHost{{Host: "app.example.test", IsPrimary: true}},
		Listeners: []ApplicationListener{
			{Port: 80, Protocol: ListenerProtocolHTTP, Enabled: true},
		},
		Upstreams: []ApplicationUpstream{
			{URL: "http://127.0.0.1:9000", Enabled: true},
		},
	}
	NormalizeApplication(&app)
	if app.Upstreams[0].Name != "primary" {
		t.Fatalf("expected default upstream name, got %+v", app.Upstreams[0])
	}
	if err := ValidateApplication(app, nil); err != nil {
		t.Fatalf("expected legacy single-upstream application to remain valid: %v", err)
	}
}

func TestValidateApplicationRoutes(t *testing.T) {
	upstreams := map[string]ApplicationUpstream{
		"primary": {Name: "primary", URL: "http://127.0.0.1:9000", Enabled: true},
		"admin":   {Name: "admin", URL: "http://127.0.0.1:9001", Enabled: true},
		"old":     {Name: "old", URL: "http://127.0.0.1:9002", Enabled: false},
	}
	valid := []ApplicationRoute{
		{Name: "API", Path: "/api/*", PathMatch: "glob", UpstreamName: "primary", Priority: 10, Enabled: true},
		{Name: "Admin", Path: "/admin", PathMatch: "prefix", UpstreamName: "admin", Priority: 20, Enabled: true},
	}
	if err := ValidateApplicationRoutes(valid, upstreams); err != nil {
		t.Fatalf("expected valid routes: %v", err)
	}

	tests := []struct {
		name   string
		routes []ApplicationRoute
	}{
		{
			name:   "missing upstream",
			routes: []ApplicationRoute{{Name: "Missing", Path: "/", PathMatch: "prefix", UpstreamName: "missing", Priority: 1, Enabled: true}},
		},
		{
			name:   "disabled upstream",
			routes: []ApplicationRoute{{Name: "Old", Path: "/", PathMatch: "prefix", UpstreamName: "old", Priority: 1, Enabled: true}},
		},
		{
			name: "duplicate priority",
			routes: []ApplicationRoute{
				{Name: "A", Path: "/a", PathMatch: "prefix", UpstreamName: "primary", Priority: 1, Enabled: true},
				{Name: "B", Path: "/b", PathMatch: "prefix", UpstreamName: "primary", Priority: 1, Enabled: true},
			},
		},
		{
			name:   "invalid path match",
			routes: []ApplicationRoute{{Name: "Bad", Path: "/api/**", PathMatch: "glob", UpstreamName: "primary", Priority: 1, Enabled: true}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateApplicationRoutes(tc.routes, upstreams); err == nil {
				t.Fatal("expected route validation to fail")
			}
		})
	}
}

func TestValidateApplicationProxyConfig(t *testing.T) {
	preserveHost := false
	config := ApplicationProxyConfig{
		Headers: []ApplicationProxyHeader{
			{Name: "X-App-Trace", Value: "$request_id"},
		},
		ConnectTimeout:   "500ms",
		ReadTimeout:      "30s",
		SendTimeout:      "1m",
		WebSocketEnabled: true,
		PreserveHost:     &preserveHost,
		ProxyBuffering:   "off",
		RequestBuffering: "on",
	}
	if err := ValidateApplicationProxyConfig(config); err != nil {
		t.Fatalf("expected valid proxy config: %v", err)
	}
	config.Headers[0].Name = "Bad Header"
	if err := ValidateApplicationProxyConfig(config); err == nil {
		t.Fatal("expected invalid proxy header name to fail")
	}
	config.Headers[0].Name = "X-App-Trace"
	config.Headers[0].Value = "ok\nproxy_pass http://evil"
	if err := ValidateApplicationProxyConfig(config); err == nil {
		t.Fatal("expected newline in proxy header value to fail")
	}
	config.Headers[0].Value = "ok"
	config.ReadTimeout = "30 seconds"
	if err := ValidateApplicationProxyConfig(config); err == nil {
		t.Fatal("expected invalid timeout to fail")
	}
}

func testCertificatePEM(t *testing.T, dnsName string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}
