package codes.grow.packages.openbao;

import java.nio.charset.StandardCharsets;

/**
 * One item of {@link Transit#encryptBatch}.
 *
 * @param plaintext bytes to encrypt
 * @param context derivation context, may be null
 * @param reference caller reference echoed in the result, may be null
 */
public record EncryptBatchItem(byte[] plaintext, byte[] context, String reference) {
  /**
   * An item without context or reference.
   *
   * @param plaintext UTF-8 text
   * @return the item
   */
  public static EncryptBatchItem of(String plaintext) {
    return new EncryptBatchItem(plaintext.getBytes(StandardCharsets.UTF_8), null, null);
  }

  @Override
  public String toString() {
    return "EncryptBatchItem{plaintext=[REDACTED], reference=" + reference + "}";
  }
}
