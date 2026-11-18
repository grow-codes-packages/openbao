package codes.grow.packages.openbao;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Seal status ({@code GET sys/seal-status}, also returned by {@code unseal}).
 *
 * @param type seal type, e.g. {@code shamir}, {@code static}
 * @param initialized whether the server is initialised
 * @param sealed whether it is sealed
 * @param threshold keys needed to unseal
 * @param shares number of key shares
 * @param progress keys entered so far
 * @param nonce unseal nonce
 * @param recoverySeal whether a recovery seal is used
 * @param version server version
 * @param clusterName cluster name
 * @param clusterId cluster id
 * @param storageType storage backend, e.g. {@code raft}
 */
public record SealStatus(
    String type,
    boolean initialized,
    boolean sealed,
    int threshold,
    int shares,
    int progress,
    String nonce,
    boolean recoverySeal,
    String version,
    String clusterName,
    String clusterId,
    String storageType) {

  /**
   * Converts a raw seal-status body.
   *
   * @param d the body
   * @return the status
   */
  public static SealStatus from(JsonNode d) {
    return new SealStatus(
        Wire.str(d, "type"),
        Wire.bool(d, "initialized"),
        Wire.bool(d, "sealed"),
        Wire.num(d, "t"),
        Wire.num(d, "n"),
        Wire.num(d, "progress"),
        Wire.str(d, "nonce"),
        Wire.bool(d, "recovery_seal"),
        Wire.str(d, "version"),
        Wire.str(d, "cluster_name"),
        Wire.str(d, "cluster_id"),
        Wire.str(d, "storage_type"));
  }
}
