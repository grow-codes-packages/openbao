package codes.grow.packages.openbao;

/**
 * One item of {@link Transit#decryptBatch}.
 *
 * @param ciphertext {@code vault:v<n>:} ciphertext
 * @param context derivation context, may be null
 * @param reference caller reference echoed in the result, may be null
 */
public record DecryptBatchItem(String ciphertext, byte[] context, String reference) {
  /**
   * An item without context or reference.
   *
   * @param ciphertext ciphertext
   * @return the item
   */
  public static DecryptBatchItem of(String ciphertext) {
    return new DecryptBatchItem(ciphertext, null, null);
  }

  @Override
  public String toString() {
    return "DecryptBatchItem{ciphertext=" + ciphertext + ", reference=" + reference + "}";
  }
}
