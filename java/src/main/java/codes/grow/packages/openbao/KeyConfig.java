package codes.grow.packages.openbao;

import java.time.Duration;

/** Settings of {@link Transit#updateKeyConfig(String, KeyConfig)}; unset fields stay unchanged. */
public final class KeyConfig {
  final Boolean deletionAllowed;
  final Integer minDecryptionVersion;
  final Integer minEncryptionVersion;
  final Boolean exportable;
  final Boolean allowPlaintextBackup;
  final Duration autoRotatePeriod;

  private KeyConfig(Builder b) {
    this.deletionAllowed = b.deletionAllowed;
    this.minDecryptionVersion = b.minDecryptionVersion;
    this.minEncryptionVersion = b.minEncryptionVersion;
    this.exportable = b.exportable;
    this.allowPlaintextBackup = b.allowPlaintextBackup;
    this.autoRotatePeriod = b.autoRotatePeriod;
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link KeyConfig}. */
  public static final class Builder {
    private Boolean deletionAllowed;
    private Integer minDecryptionVersion;
    private Integer minEncryptionVersion;
    private Boolean exportable;
    private Boolean allowPlaintextBackup;
    private Duration autoRotatePeriod;

    private Builder() {}

    /**
     * Allows {@code deleteKey}.
     *
     * @param allowed flag
     * @return this builder
     */
    public Builder deletionAllowed(boolean allowed) {
      this.deletionAllowed = allowed;
      return this;
    }

    /**
     * Sets the minimum version allowed for decryption.
     *
     * @param version version
     * @return this builder
     */
    public Builder minDecryptionVersion(int version) {
      this.minDecryptionVersion = version;
      return this;
    }

    /**
     * Sets the minimum version used for encryption (0 = latest).
     *
     * @param version version
     * @return this builder
     */
    public Builder minEncryptionVersion(int version) {
      this.minEncryptionVersion = version;
      return this;
    }

    /**
     * Allows key export (cannot be undone).
     *
     * @param exportable flag
     * @return this builder
     */
    public Builder exportable(boolean exportable) {
      this.exportable = exportable;
      return this;
    }

    /**
     * Allows plaintext backups (cannot be undone).
     *
     * @param allow flag
     * @return this builder
     */
    public Builder allowPlaintextBackup(boolean allow) {
      this.allowPlaintextBackup = allow;
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
     * Builds the settings.
     *
     * @return the settings
     */
    public KeyConfig build() {
      return new KeyConfig(this);
    }
  }
}
