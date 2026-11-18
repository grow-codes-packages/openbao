package codes.grow.packages.openbao;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.Optional;

/**
 * Node health ({@code GET sys/health}).
 *
 * @param state {@code active}, {@code standby}, {@code perfstandby}, {@code sealed} or {@code
 *     uninitialized}
 * @param initialized whether the server is initialised
 * @param sealed whether it is sealed
 * @param standby whether it is a standby node
 * @param performanceStandby whether it is a performance standby
 * @param version server version, e.g. {@code 2.7.2}
 * @param clusterName cluster name
 * @param clusterId cluster id
 * @param serverTime server time
 */
public record HealthResponse(
    String state,
    boolean initialized,
    boolean sealed,
    boolean standby,
    boolean performanceStandby,
    String version,
    String clusterName,
    String clusterId,
    Optional<Instant> serverTime) {

  /**
   * Converts a raw {@code sys/health} body.
   *
   * @param d the body
   * @return the health
   */
  public static HealthResponse from(JsonNode d) {
    boolean initialized = Wire.bool(d, "initialized");
    boolean sealed = Wire.bool(d, "sealed");
    boolean standby = Wire.bool(d, "standby");
    boolean perf = Wire.bool(d, "performance_standby");
    String state;
    if (!initialized) {
      state = "uninitialized";
    } else if (sealed) {
      state = "sealed";
    } else if (perf) {
      state = "perfstandby";
    } else if (standby) {
      state = "standby";
    } else {
      state = "active";
    }
    return new HealthResponse(
        state,
        initialized,
        sealed,
        standby,
        perf,
        Wire.str(d, "version"),
        Wire.str(d, "cluster_name"),
        Wire.str(d, "cluster_id"),
        Wire.time(d.get("server_time_utc")));
  }
}
