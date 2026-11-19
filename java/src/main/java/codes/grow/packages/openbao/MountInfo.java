package codes.grow.packages.openbao;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;

/**
 * A secrets engine or auth method mount.
 *
 * @param type engine type, e.g. {@code kv}, {@code approle}
 * @param description description
 * @param accessor mount accessor
 * @param options engine options (e.g. {@code version=2})
 * @param config mount config (TTLs, token type, ...)
 * @param local whether the mount is local to the cluster
 * @param sealWrap whether seal wrapping is on
 */
public record MountInfo(
    String type,
    String description,
    String accessor,
    Map<String, String> options,
    Map<String, String> config,
    boolean local,
    boolean sealWrap) {
  /**
   * Creates the record; maps are copied.
   *
   * @param type type
   * @param description description
   * @param accessor accessor
   * @param options options
   * @param config config
   * @param local local flag
   * @param sealWrap seal wrap flag
   */
  public MountInfo {
    options = Map.copyOf(options);
    config = Map.copyOf(config);
  }

  static MountInfo from(JsonNode m) {
    return new MountInfo(
        Wire.str(m, "type"),
        Wire.str(m, "description"),
        Wire.str(m, "accessor"),
        Wire.stringMap(m.get("options")),
        Wire.stringMap(m.get("config")),
        Wire.bool(m, "local"),
        Wire.bool(m, "seal_wrap"));
  }
}
