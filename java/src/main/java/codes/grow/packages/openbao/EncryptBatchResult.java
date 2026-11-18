package codes.grow.packages.openbao;

import java.util.Optional;
import java.util.OptionalInt;

/**
 * Result of one {@link Transit#encryptBatch} item (input order). A failed item has {@code error}.
 *
 * @param ciphertext ciphertext on success
 * @param keyVersion key version on success
 * @param reference echoed reference
 * @param error error text of a failed item
 */
public record EncryptBatchResult(
    Optional<String> ciphertext,
    OptionalInt keyVersion,
    Optional<String> reference,
    Optional<String> error) {}
