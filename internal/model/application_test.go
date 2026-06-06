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
