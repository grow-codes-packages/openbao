package codes.grow.packages.openbao;

import java.time.Duration;

/** Options of {@link Transit#createKey(String, CreateKeyOptions)}. */
public final class CreateKeyOptions {
  final String type;
  final Boolean exportable;
  final Boolean derived;
  final Duration autoRotatePeriod;
  final Boolean allowPlaintextBackup;
  final Integer keySize;

  private CreateKeyOptions(Builder b) {
    this.type = b.type;
    this.exportable = b.exportable;
    this.derived = b.derived;
    this.autoRotatePeriod = b.autoRotatePeriod;
    this.allowPlaintextBackup = b.allowPlaintextBackup;
    this.keySize = b.keySize;
  }

  /**
   * Options for a key type with every other setting at its default.
   *
   * @param type key type, e.g. {@code aes256-gcm96}, {@code chacha20-poly1305}, {@code ed25519},
   *     {@code ecdsa-p256}, {@code rsa-2048}, {@code hmac}
   * @return the options
   */
  public static CreateKeyOptions ofType(String type) {
    return builder().type(type).build();
  }

  /**
   * Starts a builder (default type {@code aes256-gcm96}).
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link CreateKeyOptions}. */
  public static final class Builder {
    private String type = "aes256-gcm96";
    private Boolean exportable;
    private Boolean derived;
    private Duration autoRotatePeriod;
    private Boolean allowPlaintextBackup;
    private Integer keySize;

    private Builder() {}

    /**
     * Sets the key type.
     *
     * @param type key type
     * @return this builder
     */
    public Builder type(String type) {
      this.type = type;
      return this;
    }

    /**
     * Allows key export.
     *
     * @param exportable flag
     * @return this builder
     */
    public Builder exportable(boolean exportable) {
      this.exportable = exportable;
      return this;
    }

    /**
     * Enables key derivation (requires a context on every call).
     *
     * @param derived flag
     * @return this builder
     */
    public Builder derived(boolean derived) {
      this.derived = derived;
      return this;
    }

    /**
     * Sets the automatic rotation period.
     *
     * @param period period (zero = off)
     * @return this builder
     */
    public Builder autoRotatePeriod(Duration period) {
      this.autoRotatePeriod = period;
      return this;
    }

    /**
     * Allows plaintext backups.
     *
     * @param allow flag
     * @return this builder
     */
    public Builder allowPlaintextBackup(boolean allow) {
      this.allowPlaintextBackup = allow;
      return this;
    }

    /**
     * Sets the key size (HMAC keys).
     *
     * @param keySize bytes
     * @return this builder
     */
    public Builder keySize(int keySize) {
      this.keySize = keySize;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public CreateKeyOptions build() {
      return new CreateKeyOptions(this);
    }
  }
}
