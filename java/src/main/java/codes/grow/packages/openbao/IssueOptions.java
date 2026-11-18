package codes.grow.packages.openbao;

import java.time.Duration;
import java.util.List;

/** Options of {@link Pki#issueCertificate} and {@link Pki#signCsr}. */
public final class IssueOptions {
  private static final IssueOptions NONE = builder().build();

  final String commonName;
  final List<String> altNames;
  final List<String> ipSans;
  final List<String> uriSans;
  final Duration ttl;
  final String format;
  final String privateKeyFormat;
  final Boolean excludeCnFromSans;

  private IssueOptions(Builder b) {
    this.commonName = b.commonName;
    this.altNames = b.altNames;
    this.ipSans = b.ipSans;
    this.uriSans = b.uriSans;
    this.ttl = b.ttl;
    this.format = b.format;
    this.privateKeyFormat = b.privateKeyFormat;
    this.excludeCnFromSans = b.excludeCnFromSans;
  }

  /**
   * Returns the empty options.
   *
   * @return the defaults
   */
  public static IssueOptions none() {
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

  private static String join(List<String> values) {
    return values == null || values.isEmpty() ? null : String.join(",", values);
  }

  String altNamesCsv() {
    return join(altNames);
  }

  String ipSansCsv() {
    return join(ipSans);
  }

  String uriSansCsv() {
    return join(uriSans);
  }

  /** Builder of {@link IssueOptions}. */
  public static final class Builder {
    private String commonName;
    private List<String> altNames;
    private List<String> ipSans;
    private List<String> uriSans;
    private Duration ttl;
    private String format;
    private String privateKeyFormat;
    private Boolean excludeCnFromSans;

    private Builder() {}

    /**
     * Sets the common name ({@code signCsr} only; defaults to the CSR subject).
     *
     * @param commonName common name
     * @return this builder
     */
    public Builder commonName(String commonName) {
      this.commonName = commonName;
      return this;
    }

    /**
     * Sets DNS / email subject alternative names.
     *
     * @param names names
     * @return this builder
     */
    public Builder altNames(String... names) {
      this.altNames = List.of(names);
      return this;
    }

    /**
     * Sets IP subject alternative names.
     *
     * @param ips addresses
     * @return this builder
     */
    public Builder ipSans(String... ips) {
      this.ipSans = List.of(ips);
      return this;
    }

    /**
     * Sets URI subject alternative names.
     *
     * @param uris URIs
     * @return this builder
     */
    public Builder uriSans(String... uris) {
      this.uriSans = List.of(uris);
      return this;
    }

    /**
     * Sets the certificate TTL.
     *
     * @param ttl TTL
     * @return this builder
     */
    public Builder ttl(Duration ttl) {
      this.ttl = ttl;
      return this;
    }

    /**
     * Sets the output format: {@code pem} (default), {@code der} or {@code pem_bundle}.
     *
     * @param format format
     * @return this builder
     */
    public Builder format(String format) {
      this.format = format;
      return this;
    }

    /**
     * Sets the private key format ({@code issueCertificate} only): {@code der} or {@code pkcs8}.
     *
     * @param privateKeyFormat format
     * @return this builder
     */
    public Builder privateKeyFormat(String privateKeyFormat) {
      this.privateKeyFormat = privateKeyFormat;
      return this;
    }

    /**
     * Leaves the common name out of the SANs.
     *
     * @param exclude flag
     * @return this builder
     */
    public Builder excludeCnFromSans(boolean exclude) {
      this.excludeCnFromSans = exclude;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public IssueOptions build() {
      return new IssueOptions(this);
    }
  }
}
