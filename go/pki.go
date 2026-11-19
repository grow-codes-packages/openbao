package openbao

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// PKI is the PKI secrets engine.
type PKI struct {
	c     *Client
	mount string
}

// PKI returns the PKI engine at mount ("" = "pki").
func (c *Client) PKI(mount string) *PKI { return &PKI{c: c, mount: mountOr(mount, "pki")} }

// Mount returns the mount path.
func (p *PKI) Mount() string { return p.mount }

// Certificate is an issued or signed certificate.
type Certificate struct {
	// Certificate is the PEM certificate.
	Certificate string
	// IssuingCA is the PEM certificate of the issuer.
	IssuingCA string
	// CAChain is the PEM chain (issuer first).
	CAChain []string
	// PrivateKey is the PEM private key (IssueCertificate only; redacted when printed).
	PrivateKey     Secret
	PrivateKeyType string
	// SerialNumber is colon-separated hex ("56:f1:...").
	SerialNumber string
	Expiration   time.Time
}

type certificateJSON struct {
	Certificate    string   `json:"certificate"`
	IssuingCA      string   `json:"issuing_ca"`
	CAChain        []string `json:"ca_chain"`
	PrivateKey     string   `json:"private_key"`
	PrivateKeyType string   `json:"private_key_type"`
	SerialNumber   string   `json:"serial_number"`
	Expiration     flexTime `json:"expiration"`
}

// IssueOptions configure IssueCertificate and SignCSR.
type IssueOptions struct {
	AltNames []string
	IPSANs   []string
	URISANs  []string
	TTL      time.Duration
	// Format is "pem" (default), "der" or "pem_bundle".
	Format string
	// PrivateKeyFormat is "der" (default) or "pkcs8" (IssueCertificate only).
	PrivateKeyFormat  string
	ExcludeCNFromSANs bool
}

func (o *IssueOptions) body(body map[string]any) {
	if o == nil {
		return
	}
	if len(o.AltNames) > 0 {
		body["alt_names"] = strings.Join(o.AltNames, ",")
	}
	if len(o.IPSANs) > 0 {
		body["ip_sans"] = strings.Join(o.IPSANs, ",")
	}
	if len(o.URISANs) > 0 {
		body["uri_sans"] = strings.Join(o.URISANs, ",")
	}
	if o.TTL > 0 {
		body["ttl"] = durationString(o.TTL)
	}
	if o.Format != "" {
		body["format"] = o.Format
	}
	if o.PrivateKeyFormat != "" {
		body["private_key_format"] = o.PrivateKeyFormat
	}
	if o.ExcludeCNFromSANs {
		body["exclude_cn_from_sans"] = true
	}
}

func (p *PKI) certCall(ctx context.Context, path, op string, body map[string]any) (*Certificate, error) {
	var d certificateJSON
	if err := p.c.callData(ctx, apiRequest{method: http.MethodPost, path: joinPath(p.mount, path), body: body, op: op}, &d); err != nil {
		return nil, err
	}
	p.c.rememberSecret(d.PrivateKey)
	return &Certificate{
		Certificate: d.Certificate, IssuingCA: d.IssuingCA, CAChain: d.CAChain,
		PrivateKey: NewSecret(d.PrivateKey), PrivateKeyType: d.PrivateKeyType,
		SerialNumber: d.SerialNumber, Expiration: d.Expiration.Time,
	}, nil
}

// IssueCertificate issues a certificate and private key for commonName with
// role (POST <mount>/issue/<role>). A name the role does not allow is a
// VALIDATION error.
func (p *PKI) IssueCertificate(ctx context.Context, role, commonName string, opts *IssueOptions) (*Certificate, error) {
	op := "pki.issueCertificate " + role
	if err := requireArg(op, "commonName", commonName); err != nil {
		return nil, err
	}
	body := map[string]any{"common_name": commonName}
	opts.body(body)
	return p.certCall(ctx, "issue/"+role, op, body)
}

// SignCSR signs a PEM certificate signing request with role (POST
// <mount>/sign/<role>). opts.AltNames etc. are added to the request; the
// common name defaults to the CSR's.
func (p *PKI) SignCSR(ctx context.Context, role, csr string, opts *IssueOptions) (*Certificate, error) {
	op := "pki.signCsr " + role
	if err := requireArg(op, "csr", csr); err != nil {
		return nil, err
	}
	body := map[string]any{"csr": csr}
	opts.body(body)
	return p.certCall(ctx, "sign/"+role, op, body)
}

// Revocation is the result of RevokeCertificate.
type Revocation struct {
	RevocationTime time.Time
	State          string
}

// RevokeCertificate revokes a certificate by serial number (POST <mount>/revoke).
// An unknown serial is a VALIDATION error.
func (p *PKI) RevokeCertificate(ctx context.Context, serial string) (*Revocation, error) {
	op := "pki.revokeCertificate"
	if err := requireArg(op, "serial", serial); err != nil {
		return nil, err
	}
	var d struct {
		RevocationTime flexTime `json:"revocation_time"`
		RFC3339        flexTime `json:"revocation_time_rfc3339"`
		State          string   `json:"state"`
	}
	if err := p.c.callData(ctx, apiRequest{method: http.MethodPost, path: joinPath(p.mount, "revoke"), body: map[string]any{"serial_number": serial}, op: op}, &d); err != nil {
		return nil, err
	}
	t := d.RFC3339.Time
	if t.IsZero() {
		t = d.RevocationTime.Time
	}
	return &Revocation{RevocationTime: t, State: d.State}, nil
}

// ReadCAChain returns the CA chain as concatenated PEM (GET <mount>/ca_chain).
func (p *PKI) ReadCAChain(ctx context.Context) (string, error) {
	res, err := p.c.send(ctx, apiRequest{method: http.MethodGet, path: joinPath(p.mount, "ca_chain"), op: "pki.readCaChain"})
	if err != nil {
		return "", err
	}
	return string(res.Body), nil
}

// CertificateInfo is the result of ReadCertificate.
type CertificateInfo struct {
	Certificate string
	// RevocationTime is zero when the certificate is not revoked.
	RevocationTime time.Time
}

// Revoked reports whether the certificate is revoked.
func (c *CertificateInfo) Revoked() bool { return !c.RevocationTime.IsZero() }

// ReadCertificate returns a certificate by serial number (NOT_FOUND when unknown).
// The serials "ca", "ca_chain" and "crl" are also accepted.
func (p *PKI) ReadCertificate(ctx context.Context, serial string) (*CertificateInfo, error) {
	op := "pki.readCertificate " + serial
	if err := requireArg(op, "serial", serial); err != nil {
		return nil, err
	}
	var d struct {
		Certificate    string   `json:"certificate"`
		RevocationTime flexTime `json:"revocation_time"`
		RFC3339        flexTime `json:"revocation_time_rfc3339"`
	}
	if err := p.c.callData(ctx, apiRequest{method: http.MethodGet, path: joinPath(p.mount, "cert", serial), op: op}, &d); err != nil {
		return nil, err
	}
	t := d.RFC3339.Time
	if t.IsZero() {
		t = d.RevocationTime.Time
	}
	return &CertificateInfo{Certificate: d.Certificate, RevocationTime: t}, nil
}

// ListCertificates returns the serial numbers of the stored certificates.
func (p *PKI) ListCertificates(ctx context.Context) ([]string, error) {
	return p.c.list(ctx, joinPath(p.mount, "certs"), "pki.listCertificates")
}

// TidyOptions configure Tidy.
type TidyOptions struct {
	// TidyCertStore removes expired certificates from storage (default true).
	TidyCertStore *bool
	// TidyRevokedCerts removes expired revoked certificates (default true).
	TidyRevokedCerts *bool
	// SafetyBuffer is how long past expiry certificates are kept (server default 72h).
	SafetyBuffer time.Duration
	// Wait polls tidy-status until this run has started and finished (interval 500 ms, bounded by ctx / WaitTimeout).
	Wait bool
	// WaitTimeout bounds Wait (default 60 s).
	WaitTimeout time.Duration
}

// TidyStatus is the state of the last tidy run.
type TidyStatus struct {
	// State is "Inactive", "Running", "Finished", "Error" or "Cancelled".
	State string
	Error string
	// TimeStarted and TimeFinished are zero when unknown.
	TimeStarted             time.Time
	TimeFinished            time.Time
	CertStoreDeletedCount   int
	RevokedCertDeletedCount int
}

// Tidy starts a tidy run (POST <mount>/tidy, answered 202) and optionally waits for it.
func (p *PKI) Tidy(ctx context.Context, opts *TidyOptions) (*TidyStatus, error) {
	o := TidyOptions{}
	if opts != nil {
		o = *opts
	}
	body := map[string]any{"tidy_cert_store": true, "tidy_revoked_certs": true}
	if o.TidyCertStore != nil {
		body["tidy_cert_store"] = *o.TidyCertStore
	}
	if o.TidyRevokedCerts != nil {
		body["tidy_revoked_certs"] = *o.TidyRevokedCerts
	}
	if o.SafetyBuffer > 0 {
		body["safety_buffer"] = durationString(o.SafetyBuffer)
	}
	var before time.Time
	if o.Wait {
		if st, err := p.TidyStatus(ctx); err == nil {
			before = st.TimeStarted
		}
	}
	if _, err := p.c.call(ctx, apiRequest{method: http.MethodPost, path: joinPath(p.mount, "tidy"), body: body, op: "pki.tidy"}); err != nil {
		return nil, err
	}
	if !o.Wait {
		return &TidyStatus{State: "Running"}, nil
	}
	timeout := o.WaitTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return PollUntil(ctx, "pki.tidy", timeout, 500*time.Millisecond, func(ctx context.Context) (*TidyStatus, bool, error) {
		st, err := p.TidyStatus(ctx)
		if err != nil {
			return nil, false, err
		}
		started := st.State != "Inactive" && (before.IsZero() || st.TimeStarted.After(before))
		return st, started && st.State != "Running", nil
	})
}

// TidyStatus returns the state of the current or last tidy run.
func (p *PKI) TidyStatus(ctx context.Context) (*TidyStatus, error) {
	var d struct {
		State                   string   `json:"state"`
		Error                   *string  `json:"error"`
		TimeStarted             flexTime `json:"time_started"`
		TimeFinished            flexTime `json:"time_finished"`
		CertStoreDeletedCount   int      `json:"cert_store_deleted_count"`
		RevokedCertDeletedCount int      `json:"revoked_cert_deleted_count"`
	}
	if err := p.c.callData(ctx, apiRequest{method: http.MethodGet, path: joinPath(p.mount, "tidy-status"), op: "pki.tidyStatus"}, &d); err != nil {
		return nil, err
	}
	st := &TidyStatus{State: d.State, TimeStarted: d.TimeStarted.Time, TimeFinished: d.TimeFinished.Time, CertStoreDeletedCount: d.CertStoreDeletedCount, RevokedCertDeletedCount: d.RevokedCertDeletedCount}
	if d.Error != nil {
		st.Error = *d.Error
	}
	return st, nil
}
