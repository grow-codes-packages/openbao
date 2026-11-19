package codes.grow.packages.openbao.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.openbao.CertificateInfo;
import codes.grow.packages.openbao.IssueOptions;
import codes.grow.packages.openbao.IssuedCertificate;
import codes.grow.packages.openbao.OpenBaoClient;
import codes.grow.packages.openbao.Pki;
import codes.grow.packages.openbao.RevocationInfo;
import codes.grow.packages.openbao.SignedCertificate;
import codes.grow.packages.openbao.TidyOptions;
import codes.grow.packages.openbao.TidyStatus;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.ValidationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PkiIntegrationTest {
  private static X509Certificate parse(String pem) throws Exception {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
  }

  @Test
  void issueSignRevokeTidy() throws Exception {
    Map<String, String> env = Env.load();
    String run = Env.run();
    String domain = Env.get(env, "PKI_DOMAIN");
    try (OpenBaoClient c = Env.root(env)) {
      Pki pki = c.pki(Env.get(env, "PKI_MOUNT"));
      String role = Env.get(env, "PKI_ROLE");
      IssuedCertificate cert =
          pki.issueCertificate(
              role,
              "svc-" + run + "." + domain,
              IssueOptions.builder()
                  .altNames("alt-" + run + "." + domain)
                  .ipSans("127.0.0.1")
                  .ttl(Duration.ofHours(1))
                  .build());
      X509Certificate x = parse(cert.certificate());
      assertTrue(x.getSubjectX500Principal().getName().contains("svc-" + run));
      X509Certificate ca = parse(pki.readCaChain());
      x.verify(ca.getPublicKey());
      assertFalse(cert.privateKey().reveal().isEmpty());
      assertTrue(cert.expiration().isPresent());
      assertThrows(
          ValidationException.class, () -> pki.issueCertificate(role, "evil.example.com"));

      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(new ECGenParameterSpec("secp256r1"));
      KeyPair kp = g.generateKeyPair();
      String csr = Csr.pem(kp, "csr-" + run + "." + domain);
      SignedCertificate signed = pki.signCsr(role, csr);
      X509Certificate sx = parse(signed.certificate());
      assertEquals(kp.getPublic(), sx.getPublicKey());
      SignedCertificate named =
          pki.signCsr(role, csr, IssueOptions.builder().commonName("other-" + run + "." + domain).build());
      // the role keeps the CSR subject (use_csr_common_name defaults to true)
      assertEquals(kp.getPublic(), parse(named.certificate()).getPublicKey());
      assertThrows(ValidationException.class, () -> pki.signCsr(role, "garbage"));

      assertTrue(pki.listCertificates().contains(cert.serialNumber()));
      CertificateInfo info = pki.readCertificate(cert.serialNumber());
      assertTrue(info.revocationTime().isEmpty());
      RevocationInfo rev = pki.revokeCertificate(cert.serialNumber());
      assertEquals("revoked", rev.state());
      assertTrue(pki.readCertificate(cert.serialNumber()).revocationTime().isPresent());
      assertThrows(ValidationException.class, () -> pki.revokeCertificate("ff:ff:ff:ff"));
      assertThrows(NotFoundException.class, () -> pki.readCertificate("ff:ff:ff:ff"));

      TidyStatus tidy =
          pki.tidy(TidyOptions.builder().safetyBuffer(Duration.ofSeconds(1)).build());
      assertEquals("Finished", tidy.state());
      assertTrue(tidy.error().isEmpty());
      assertFalse(pki.tidyStatus().state().isEmpty());
    }
  }

  /** Minimal PKCS#10 encoder for an EC P-256 key (test only). */
  static final class Csr {
    private Csr() {}

    static byte[] tlv(int tag, byte[]... parts) {
      ByteArrayOutputStream body = new ByteArrayOutputStream();
      for (byte[] p : parts) {
        body.writeBytes(p);
      }
      byte[] b = body.toByteArray();
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.write(tag);
      if (b.length < 128) {
        out.write(b.length);
      } else if (b.length < 256) {
        out.write(0x81);
        out.write(b.length);
      } else {
        out.write(0x82);
        out.write(b.length >> 8);
        out.write(b.length & 0xff);
      }
      out.writeBytes(b);
      return out.toByteArray();
    }

    static String pem(KeyPair kp, String cn) throws Exception {
      byte[] oidCn = {0x06, 0x03, 0x55, 0x04, 0x03};
      byte[] name =
          tlv(0x30, tlv(0x31, tlv(0x30, oidCn, tlv(0x0c, cn.getBytes(StandardCharsets.UTF_8)))));
      byte[] info =
          tlv(0x30, new byte[] {0x02, 0x01, 0x00}, name, kp.getPublic().getEncoded(), new byte[] {(byte) 0xa0, 0x00});
      java.security.Signature s = java.security.Signature.getInstance("SHA256withECDSA");
      s.initSign(kp.getPrivate());
      s.update(info);
      byte[] sig = s.sign();
      byte[] ecdsaSha256 = {0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x04, 0x03, 0x02};
      byte[] bitString = new byte[sig.length + 1];
      System.arraycopy(sig, 0, bitString, 1, sig.length);
      byte[] der = tlv(0x30, info, tlv(0x30, ecdsaSha256), tlv(0x03, bitString));
      return "-----BEGIN CERTIFICATE REQUEST-----\n"
          + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
          + "\n-----END CERTIFICATE REQUEST-----\n";
    }
  }
}
