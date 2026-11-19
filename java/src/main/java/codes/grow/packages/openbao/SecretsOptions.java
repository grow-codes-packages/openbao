package codes.grow.packages.openbao;

/** Options of {@link OpenBaoClient#secrets(SecretsOptions)}. */
public final class SecretsOptions {
  final String mount;
  final String path;
  final String valueField;

  private SecretsOptions(Builder b) {
    this.mount = b.mount;
    this.path = b.path;
    this.valueField = b.valueField;
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link SecretsOptions}. */
  public static final class Builder {
    private String mount;
    private String path;
    private String valueField;

    private Builder() {}

    /**
     * Sets the KV mount (default {@link OpenBaoConfig#kvMount()}, i.e. {@code secret}).
     *
     * @param mount mount path
     * @return this builder
     */
    public Builder mount(String mount) {
      this.mount = mount;
      return this;
    }

    /**
     * Sets the base path inside the mount that names are relative to (default {@link
     * OpenBaoConfig#secretsPath()}).
     *
     * @param path base path
     * @return this builder
     */
    public Builder path(String path) {
      this.path = path;
      return this;
    }

    /**
     * Sets the data field that holds the value (default {@link OpenBaoConfig#valueField()}).
     *
     * @param valueField field name
     * @return this builder
     */
    public Builder valueField(String valueField) {
      this.valueField = valueField;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public SecretsOptions build() {
      return new SecretsOptions(this);
    }
  }
}
