package codes.grow.packages.openbao;

import java.time.Instant;
import java.util.Optional;

/**
 * Leader status ({@code GET sys/leader}).
 *
 * @param haEnabled whether high availability is enabled
 * @param isSelf whether this node is the leader
 * @param activeTime when the leader became active
 * @param leaderAddress leader API address
 * @param leaderClusterAddress leader cluster address
 */
public record LeaderStatus(
    boolean haEnabled,
    boolean isSelf,
    Optional<Instant> activeTime,
    String leaderAddress,
    String leaderClusterAddress) {}
