package codes.grow.packages.openbao;

/**
 * A transit signature.
 *
 * @param signature {@code vault:v<keyVersion>:<base64>}
 * @param keyVersion key version used
 */
public record Signature(String signature, int keyVersion) {}
