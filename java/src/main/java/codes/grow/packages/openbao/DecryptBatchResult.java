package codes.grow.packages.openbao;

import java.util.Optional;

/**
 * Result of one {@link Transit#decryptBatch} item (input order). A failed item has {@code error}.
 * The plaintext is never printed.
 *
 * @param plaintext decrypted bytes on success
 * @param reference echoed reference
 * @param error error text of a failed item
 */
public record DecryptBatchResult(
    Optional<byte[]> plaintext, Optional<String> reference, Optional<String> error) {
  @Override
  public String toString() {
    return "DecryptBatchResult{plaintext="
        + (plaintext.isPresent() ? "[REDACTED]" : "none")
        + ", reference="
        + reference
        + ", error="
        + error
        + "}";
  }
}
