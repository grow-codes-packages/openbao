# PKI

Certificates from a PKI secrets engine (`client.pki(mount = "pki")`).

| Function | What it does |
| - | - |
| `issueCertificate(role, commonName, options?)` | new key pair + certificate: `certificate`, `issuingCa`, `caChain`, `privateKey` (redacted), `privateKeyType`, `serialNumber`, `expiration`; options `altNames`, `ipSans`, `uriSans`, `ttl`, `format`, `privateKeyFormat`, `excludeCnFromSans`; a name the role does not allow → `VALIDATION` |
| `signCsr(role, csr, options?)` | signs a PEM CSR (same result without the private key); a bad CSR → `VALIDATION` |
| `revokeCertificate(serial)` | `revocationTime`; unknown serial → `VALIDATION` |
| `readCaChain()` | PEM text of the CA chain |
| `readCertificate(serial)` | PEM certificate and revocation time (empty when not revoked); unknown → `NOT_FOUND` |
| `listCertificates()` | serial numbers (colon hex) |
| `tidy(options?)` / `tidyStatus()` | starts the asynchronous tidy (`tidyCertStore`, `tidyRevokedCerts`, `safetyBuffer`) / polls its state (`Running`, `Finished`) |

## Issue, inspect and revoke a certificate

=== "TypeScript"

    ```ts
    const pki = client.pki();
    const cert = await pki.issueCertificate("web", "app.example.test", {
      altNames: ["www.example.test"],
      ttlMs: 3_600_000,
    });
    console.log(cert.serialNumber, cert.certificate);
    const chain = await pki.readCaChain();
    await pki.revokeCertificate(cert.serialNumber);
    console.log((await pki.readCertificate(cert.serialNumber)).revocationTime); // a Date
    ```

=== "Rust"

    ```rust
    use grow_openbao::IssueOptions;

    let pki = client.pki();
    let cert = pki
        .issue_certificate(
            "web",
            "app.example.test",
            Some(&IssueOptions {
                alt_names: vec!["www.example.test".into()],
                ttl: Some(Duration::from_secs(3600)),
                ..Default::default()
            }),
        )
        .await?;
    let chain = pki.read_ca_chain().await?;
    pki.revoke_certificate(&cert.serial_number).await?;
    ```

=== "Go"

    ```go
    pki := client.PKI("pki")
    cert, err := pki.IssueCertificate(ctx, "web", "app.example.test", &openbao.IssueOptions{
        AltNames: []string{"www.example.test"}, TTL: time.Hour,
    })
    if err != nil {
        return err
    }
    chain, err := pki.ReadCAChain(ctx)
    _, err = pki.RevokeCertificate(ctx, cert.SerialNumber)
    ```

=== "Python"

    ```python
    pki = client.pki()
    cert = pki.issue_certificate("web", "app.example.test", alt_names=["www.example.test"], ttl_s=3600)
    chain = pki.read_ca_chain()
    pki.revoke_certificate(cert.serial_number)
    assert pki.read_certificate(cert.serial_number).revoked
    ```

=== "Java"

    ```java
    Pki pki = client.pki();
    IssuedCertificate cert =
        pki.issueCertificate(
            "web",
            "app.example.test",
            IssueOptions.builder().altNames("www.example.test").ttl(Duration.ofHours(1)).build());
    String chain = pki.readCaChain();
    pki.revokeCertificate(cert.serialNumber());
    ```
