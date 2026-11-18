package codes.grow.packages.openbao;

/**
 * A transit ciphertext.
 *
 * @param ciphertext {@code vault:v<keyVersion>:<base64>}
 * @param keyVersion key version used
 */
public record Ciphertext(String ciphertext, int keyVersion) {}
