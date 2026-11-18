package codes.grow.packages.openbao;

/**
 * Optional parameters of transit operations. Each operation reads only the fields it supports:
 * {@code context} (encrypt, decrypt, rewrap, batch, data keys, sign, verify), {@code keyVersion}
 * (encrypt, rewrap, hmac, sign), {@code associatedData} (encrypt, decrypt with AEAD keys), {@code
 * hashAlgorithm} (hmac, sign, verify), {@code signatureAlgorithm} and {@code prehashed} (sign,
 * verify).
 */
public final class TransitOptions {
  private static final TransitOptions NONE = builder().build();

  final byte[] context;
  final Integer keyVersion;
  final byte[] associatedData;
  final String hashAlgorithm;
  final String signatureAlgorithm;
  final Boolean prehashed;

  private TransitOptions(Builder b) {
    this.context = b.context;
    this.keyVersion = b.keyVersion;
    this.associatedData = b.associatedData;
    this.hashAlgorithm = b.hashAlgorithm;
    this.signatureAlgorithm = b.signatureAlgorithm;
    this.prehashed = b.prehashed;
  }

  /**
   * Returns the empty options.
   *
   * @return the defaults
   */
  public static TransitOptions none() {
    return NONE;
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link TransitOptions}. */
  public static final class Builder {
    private byte[] context;
    private Integer keyVersion;
    private byte[] associatedData;
    private String hashAlgorithm;
    private String signatureAlgorithm;
    private Boolean prehashed;

    private Builder() {}

    /**
     * Sets the key derivation context (derived keys).
     *
     * @param context context bytes
     * @return this builder
     */
    public Builder context(byte[] context) {
      this.context = context.clone();
      return this;
    }

    /**
     * Uses a specific key version.
     *
     * @param keyVersion version
     * @return this builder
     */
    public Builder keyVersion(int keyVersion) {
      this.keyVersion = keyVersion;
      return this;
    }

    /**
     * Sets associated data (AEAD keys).
     *
     * @param associatedData bytes
     * @return this builder
     */
    public Builder associatedData(byte[] associatedData) {
      this.associatedData = associatedData.clone();
      return this;
    }

    /**
     * Sets the hash algorithm, e.g. {@code sha2-256}, {@code sha2-512}.
     *
     * @param hashAlgorithm algorithm
     * @return this builder
     */
    public Builder hashAlgorithm(String hashAlgorithm) {
      this.hashAlgorithm = hashAlgorithm;
      return this;
    }

    /**
     * Sets the RSA signature algorithm: {@code pss} or {@code pkcs1v15}.
     *
     * @param signatureAlgorithm algorithm
     * @return this builder
     */
    public Builder signatureAlgorithm(String signatureAlgorithm) {
      this.signatureAlgorithm = signatureAlgorithm;
      return this;
    }

    /**
     * Marks the input as already hashed.
     *
     * @param prehashed flag
     * @return this builder
     */
    public Builder prehashed(boolean prehashed) {
      this.prehashed = prehashed;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public TransitOptions build() {
      return new TransitOptions(this);
    }
  }
}
