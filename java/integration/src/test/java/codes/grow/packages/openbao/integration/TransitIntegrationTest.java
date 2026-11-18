package codes.grow.packages.openbao.integration;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.openbao.Ciphertext;
import codes.grow.packages.openbao.CreateKeyOptions;
import codes.grow.packages.openbao.DataKey;
import codes.grow.packages.openbao.DecryptBatchItem;
import codes.grow.packages.openbao.DecryptBatchResult;
import codes.grow.packages.openbao.EncryptBatchItem;
import codes.grow.packages.openbao.EncryptBatchResult;
import codes.grow.packages.openbao.KeyConfig;
import codes.grow.packages.openbao.OpenBaoClient;
import codes.grow.packages.openbao.Signature;
import codes.grow.packages.openbao.Transit;
import codes.grow.packages.openbao.TransitKey;
import codes.grow.packages.openbao.TransitOptions;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.ValidationException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TransitIntegrationTest {
  private static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  @Test
  void keysAndEncryption() {
    Map<String, String> env = Env.load();
    String name = "java-" + Env.run();
    try (OpenBaoClient c = Env.root(env)) {
      Transit t = c.transit(Env.get(env, "TRANSIT_MOUNT"));
      TransitKey k = t.createKey(name);
      assertEquals("aes256-gcm96", k.type());
      assertEquals(1, k.latestVersion());
      assertEquals(name, t.readKey(name).name());
      assertTrue(t.listKeys().contains(name));
      assertEquals(1, t.listKeys(null, 1).size());

      Ciphertext ct = t.encrypt(name, "hello");
      assertTrue(ct.ciphertext().startsWith("vault:v1:"));
      assertArrayEquals(utf8("hello"), t.decrypt(name, ct.ciphertext()));
      assertEquals(2, t.rotateKey(name).latestVersion());
      Ciphertext re = t.rewrap(name, ct.ciphertext());
      assertTrue(re.ciphertext().startsWith("vault:v2:"));
      assertArrayEquals(utf8("hello"), t.decrypt(name, re.ciphertext()));
      Ciphertext v1 = t.encrypt(name, utf8("old"), TransitOptions.builder().keyVersion(1).build());
      assertEquals(1, v1.keyVersion());

      List<EncryptBatchResult> enc =
          t.encryptBatch(
              name,
              List.of(
                  EncryptBatchItem.of("one"),
                  new EncryptBatchItem(utf8("two"), null, "r2")));
      assertEquals("r2", enc.get(1).reference().get());
      List<DecryptBatchResult> dec =
          t.decryptBatch(
              name,
              List.of(
                  DecryptBatchItem.of(enc.get(0).ciphertext().get()),
                  DecryptBatchItem.of("vault:v1:AAAA")));
      assertArrayEquals(utf8("one"), dec.get(0).plaintext().get());
      assertTrue(dec.get(1).error().isPresent());

      DataKey dk = t.generateDataKey(name);
      assertEquals(32, dk.plaintext().get().length);
      assertArrayEquals(dk.plaintext().get(), t.decrypt(name, dk.ciphertext()));
      DataKey wrapped = t.generateDataKey(name, false, 128);
      assertTrue(wrapped.plaintext().isEmpty());
      assertEquals(16, t.decrypt(name, wrapped.ciphertext()).length);

      t.updateKeyConfig(name, KeyConfig.builder().minDecryptionVersion(2).build());
      assertThrows(ValidationException.class, () -> t.decrypt(name, v1.ciphertext()));
      assertThrows(ValidationException.class, () -> t.deleteKey(name));
      assertTrue(t.updateKeyConfig(name, KeyConfig.builder().deletionAllowed(true).build()).deletionAllowed());
      t.deleteKey(name);
      assertThrows(NotFoundException.class, () -> t.readKey(name));
    }
  }

  @Test
  void signHmacHashRandom() throws Exception {
    Map<String, String> env = Env.load();
    String hmacKey = "java-hmac-" + Env.run();
    try (OpenBaoClient c = Env.root(env)) {
      Transit t = c.transit();
      Signature sig = t.sign(Env.get(env, "TRANSIT_SIGN_KEY"), utf8("sign-me"));
      assertTrue(t.verify(Env.get(env, "TRANSIT_SIGN_KEY"), utf8("sign-me"), sig.signature()));
      assertFalse(t.verify(Env.get(env, "TRANSIT_SIGN_KEY"), utf8("other"), sig.signature()));
      TransitOptions rsa =
          TransitOptions.builder().hashAlgorithm("sha2-256").signatureAlgorithm("pkcs1v15").build();
      Signature rsaSig = t.sign(Env.get(env, "TRANSIT_RSA_KEY"), utf8("rsa"), rsa);
      assertTrue(t.verify(Env.get(env, "TRANSIT_RSA_KEY"), utf8("rsa"), rsaSig.signature(), rsa));
      assertThrows(
          ValidationException.class, () -> t.sign(Env.get(env, "TRANSIT_AES_KEY"), utf8("x")));

      t.createKey(hmacKey, CreateKeyOptions.builder().type("hmac").keySize(32).build());
      String mac = t.hmac(Env.get(env, "TRANSIT_AES_KEY"), utf8("data"));
      assertTrue(mac.startsWith("vault:v"));
      assertTrue(t.verifyHmac(Env.get(env, "TRANSIT_AES_KEY"), utf8("data"), mac));
      assertFalse(t.verifyHmac(Env.get(env, "TRANSIT_AES_KEY"), utf8("tampered"), mac));
      String mac512 =
          t.hmac(hmacKey, utf8("data"), TransitOptions.builder().hashAlgorithm("sha2-512").build());
      assertNotEquals(mac, mac512);

      String expected =
          HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(utf8("hash-me")));
      assertEquals(expected, t.hash(utf8("hash-me")));
      assertEquals(
          java.util.Base64.getEncoder()
              .encodeToString(MessageDigest.getInstance("SHA-512").digest(utf8("hash-me"))),
          t.hash(utf8("hash-me"), "sha2-512", "base64"));
      assertEquals(16, java.util.Base64.getDecoder().decode(t.randomBytes(16)).length);
      assertEquals(16, t.randomBytes(8, "hex").length());
    }
  }
}
