package codes.grow.packages.openbao;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A transit key ({@code GET transit/keys/<name>}).
 *
 * @param name key name
 * @param type key type, e.g. {@code aes256-gcm96}, {@code ed25519}
 * @param keys version to creation time (unix seconds as text) or, for asymmetric keys, the JSON of
 *     the version entry (with {@code public_key})
 * @param latestVersion latest version
 * @param minDecryptionVersion minimum version allowed for decryption
 * @param minEncryptionVersion minimum version used for encryption (0 = latest)
 * @param minAvailableVersion oldest version still stored
 * @param deletionAllowed whether {@code deleteKey} is allowed
 * @param exportable whether the key can be exported
 * @param derived whether key derivation is used
 * @param supportsEncryption encryption support
 * @param supportsDecryption decryption support
 * @param supportsSigning signing support
 * @param supportsDerivation derivation support
 * @param autoRotatePeriod automatic rotation period (zero = off)
 */
public record TransitKey(
    String name,
    String type,
    Map<String, String> keys,
    int latestVersion,
    int minDecryptionVersion,
    int minEncryptionVersion,
    int minAvailableVersion,
    boolean deletionAllowed,
    boolean exportable,
    boolean derived,
    boolean supportsEncryption,
    boolean supportsDecryption,
    boolean supportsSigning,
    boolean supportsDerivation,
    Duration autoRotatePeriod) {
  /**
   * Creates the record; the map is copied.
   *
   * @param name name
   * @param type type
   * @param keys keys
   * @param latestVersion latest version
   * @param minDecryptionVersion min decryption version
   * @param minEncryptionVersion min encryption version
   * @param minAvailableVersion min available version
   * @param deletionAllowed deletion flag
   * @param exportable export flag
   * @param derived derived flag
   * @param supportsEncryption encryption flag
   * @param supportsDecryption decryption flag
   * @param supportsSigning signing flag
   * @param supportsDerivation derivation flag
   * @param autoRotatePeriod rotation period
   */
  public TransitKey {
    keys = Map.copyOf(keys);
  }

  static TransitKey from(JsonNode d) {
    Map<String, String> keys = new LinkedHashMap<>(Wire.stringMap(d.get("keys")));
    return new TransitKey(
        Wire.str(d, "name"),
        Wire.str(d, "type"),
        keys,
        Wire.num(d, "latest_version"),
        Wire.num(d, "min_decryption_version"),
        Wire.num(d, "min_encryption_version"),
        Wire.num(d, "min_available_version"),
        Wire.bool(d, "deletion_allowed"),
        Wire.bool(d, "exportable"),
        Wire.bool(d, "derived"),
        Wire.bool(d, "supports_encryption"),
        Wire.bool(d, "supports_decryption"),
        Wire.bool(d, "supports_signing"),
        Wire.bool(d, "supports_derivation"),
        Wire.vaultDuration(d.get("auto_rotate_period")));
  }
}
