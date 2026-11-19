package codes.grow.packages.openbao;

import static codes.grow.packages.openbao.Fixtures.enqueue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.openbao.core.AuthenticationException;
import codes.grow.packages.openbao.core.ConflictException;
import codes.grow.packages.openbao.core.MockServer;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.PermissionDeniedException;
import codes.grow.packages.openbao.core.UnavailableException;
import codes.grow.packages.openbao.core.UnsupportedException;
import codes.grow.packages.openbao.core.ValidationException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class KvTest {
  private MockServer server;
  private OpenBaoClient client;

  @BeforeEach
  void start() throws Exception {
    server = MockServer.start();
    client = Fixtures.client(server).build();
  }

  @AfterEach
  void stop() {
    client.close();
    server.close();
  }

  @Test
  void v2ReadWritePatchAndMetadata() {
    KvV2 kv = client.kvV2("secret/");
    assertThat(kv.mount()).isEqualTo("secret");
    assertThat(kv.version()).isEqualTo(2);
    assertThat(kv.toString()).isEqualTo("KvV2(secret)");
    enqueue(server, "kvV2.read.ok");
    KvSecret s = kv.read("sdk/test/alpha");
    assertThat(s.data()).containsEntry("a", "1").containsEntry("b", "2");
    assertThat(s.metadata().get().version()).isEqualTo(1);
    assertThat(s.metadata().get().createdTime()).isPresent();
    assertThat(s.metadata().get().deleted()).isFalse();
    assertThat(s.toString()).doesNotContain("\"1\"").contains("[REDACTED]");
    assertThat(server.requests().get(0).uri()).isEqualTo("/v1/secret/data/sdk/test/alpha");
    assertThat(server.requests().get(0).header("X-Vault-Token")).isEqualTo("root-token-1234");

    enqueue(server, "kvV2.read.version");
    kv.read("sdk/test/alpha", 1);
    assertThat(server.requests().get(1).uri()).endsWith("?version=1");

    enqueue(server, "kvV2.write.no-options");
    assertThat(kv.write("sdk/test/beta", Map.of("v", "b")).get().version()).isEqualTo(1);
    assertThat(server.requests().get(2).body()).isEqualTo("{\"data\":{\"v\":\"b\"}}");

    enqueue(server, "kvV2.write.cas-ok");
    kv.write("sdk/test/beta", Map.of("v", "c"), 1);
    assertThat(server.requests().get(3).body()).contains("\"options\":{\"cas\":1}");

    enqueue(server, "kvV2.write.cas-mismatch");
    assertThatThrownBy(() -> kv.write("sdk/test/beta", Map.of("a", "x"), 0))
        .isInstanceOf(ConflictException.class);

    enqueue(server, "kvV2.patch.ok");
    assertThat(kv.patch("sdk/test/alpha", Map.of("c", "3")).version()).isPositive();
    assertThat(server.requests().get(5).method()).isEqualTo("PATCH");
    assertThat(server.requests().get(5).header("Content-Type"))
        .isEqualTo("application/merge-patch+json");

    enqueue(server, "kvV2.patch.cas-mismatch");
    assertThatThrownBy(() -> kv.patch("sdk/test/alpha", Map.of("c", "3"), 9))
        .isInstanceOf(ConflictException.class);

    enqueue(server, "kvV2.readMetadata.ok");
    KvMetadata m = kv.readMetadata("sdk/test/alpha");
    assertThat(m.currentVersion()).isEqualTo(3);
    assertThat(m.maxVersions()).isEqualTo(5);
    assertThat(m.deleteVersionAfter()).isEqualTo(Duration.ofHours(720));
    assertThat(m.customMetadata()).containsEntry("owner", "sdk");
    assertThat(m.versions()).containsKeys(1, 2);
    assertThat(m.createdTime()).isPresent();

    enqueue(server, "kvV2.writeMetadata.ok");
    kv.writeMetadata(
        "sdk/test/alpha",
        KvMetadataOptions.builder()
            .maxVersions(5)
            .casRequired(false)
            .deleteVersionAfter(Duration.ofHours(720))
            .customMetadata(Map.of("owner", "sdk"))
            .build());
    assertThat(server.requests().get(8).body())
        .contains("\"max_versions\":5")
        .contains("\"delete_version_after\":\"2592000s\"")
        .contains("\"custom_metadata\":{\"owner\":\"sdk\"}");
  }

  @Test
  void v2DeleteVersionsAndList() {
    KvV2 kv = client.kvV2("secret");
    enqueue(server, "kvV2.delete.ok");
    kv.delete("a/b");
    enqueue(server, "kvV2.deleteVersions.ok");
    kv.deleteVersions("a/b", List.of(1));
    enqueue(server, "kvV2.undelete.ok");
    kv.undelete("a/b", List.of(3));
    enqueue(server, "kvV2.destroy.ok");
    kv.destroy("a/b", List.of(1));
    enqueue(server, "kvV2.deleteMetadata.ok");
    kv.deleteMetadata("a/b");
    List<MockServer.Recorded> r = server.requests();
    assertThat(r.get(0).method()).isEqualTo("DELETE");
    assertThat(r.get(0).uri()).isEqualTo("/v1/secret/data/a/b");
    assertThat(r.get(1).uri()).isEqualTo("/v1/secret/delete/a/b");
    assertThat(r.get(1).body()).isEqualTo("{\"versions\":[1]}");
    assertThat(r.get(2).uri()).isEqualTo("/v1/secret/undelete/a/b");
    assertThat(r.get(3).method()).isEqualTo("PUT");
    assertThat(r.get(3).uri()).isEqualTo("/v1/secret/destroy/a/b");
    assertThat(r.get(4).uri()).isEqualTo("/v1/secret/metadata/a/b");
    assertThatThrownBy(() -> kv.deleteVersions("a/b", List.of()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> kv.destroy("a/b", List.of(0))).isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> kv.undelete("a/b", null)).isInstanceOf(ValidationException.class);

    enqueue(server, "kvV2.list.ok");
    assertThat(kv.list("sdk/test")).containsExactly("alpha", "beta", "dir/");
    assertThat(server.requests().get(5).uri()).isEqualTo("/v1/secret/metadata/sdk/test/?list=true");
    enqueue(server, "kvV2.list.paginated-limit");
    kv.list("sdk/test", "alpha", 1);
    assertThat(server.requests().get(6).uri()).contains("after=alpha").contains("limit=1");
    enqueue(server, "kvV2.list.not-found");
    assertThat(kv.list(null)).isEmpty();
    server.enqueue(403, "{\"errors\":[\"1 error occurred:\\n\\t* permission denied\\n\\n\"]}");
    assertThatThrownBy(() -> kv.list("x")).isInstanceOf(PermissionDeniedException.class);
  }

  @Test
  void v2ReadMissingAndDeleted() {
    KvV2 kv = client.kvV2("secret");
    enqueue(server, "kvV2.read.not-found");
    assertThatThrownBy(() -> kv.read("nope")).isInstanceOf(NotFoundException.class);
    enqueue(server, "kvV2.read.deleted");
    assertThatThrownBy(() -> kv.read("gone")).isInstanceOf(NotFoundException.class);
    server.enqueue(200, "{\"data\":{\"data\":null,\"metadata\":{\"version\":2}}}");
    assertThatThrownBy(() -> kv.read("gone")).isInstanceOf(NotFoundException.class);
    server.enqueue(200, "{\"data\":{\"data\":{\"x\":1}}}");
    assertThat(kv.read("nometa").metadata()).isEmpty();
    server.enqueue(200, "{}");
    assertThatThrownBy(() -> kv.read("bad")).isInstanceOf(UnavailableException.class);
    assertThatThrownBy(() -> kv.read(" ")).isInstanceOf(ValidationException.class);
    enqueue(server, "kvV2.read.permission-denied");
    assertThatThrownBy(() -> kv.read("sdk/denied/hello"))
        .isInstanceOf(PermissionDeniedException.class);
    enqueue(server, "kvV2.read.missing-token");
    assertThatThrownBy(() -> kv.read("x")).isInstanceOf(AuthenticationException.class);
    server.enqueue(403, "{\"errors\":[]}");
    assertThatThrownBy(() -> kv.read("x")).isInstanceOf(AuthenticationException.class);
    server.enqueue(403, "{\"errors\":[\"invalid token\"]}");
    assertThatThrownBy(() -> kv.read("x")).isInstanceOf(AuthenticationException.class);
    enqueue(server, "kvV2.patch.wrong-content-type");
    assertThatThrownBy(() -> kv.patch("x", Map.of("a", 1))).isInstanceOf(ValidationException.class);
    enqueue(server, "kvV2.write.cas-required");
    assertThatThrownBy(() -> kv.write("x", Map.of("a", 1))).isInstanceOf(ValidationException.class);
  }

  @Test
  void v1Operations() {
    KvV1 kv = client.kvV1("kv1");
    assertThat(kv.version()).isEqualTo(1);
    assertThat(kv.mount()).isEqualTo("kv1");
    assertThat(kv.toString()).isEqualTo("KvV1(kv1)");
    enqueue(server, "kvV1.read.ok");
    KvSecret s = kv.read("sdk/test/alpha");
    assertThat(s.data()).containsEntry("a", "1").containsEntry("n", 2);
    assertThat(s.metadata()).isEmpty();
    enqueue(server, "kvV1.write.ok");
    assertThat(kv.write("sdk/with space", Map.of("a", "1"))).isEmpty();
    assertThat(server.requests().get(1).uri()).isEqualTo("/v1/kv1/sdk/with%20space");
    enqueue(server, "kvV1.delete.ok");
    kv.delete("sdk/test/alpha");
    enqueue(server, "kvV1.list.ok");
    assertThat(kv.list("sdk/test")).isNotEmpty();
    assertThat(server.requests().get(3).uri()).isEqualTo("/v1/kv1/sdk/test/?list=true");
    enqueue(server, "kvV1.list.not-found");
    assertThat(kv.list("missing", null, null)).isEmpty();
    enqueue(server, "kvV1.read.not-found");
    assertThatThrownBy(() -> kv.read("missing")).isInstanceOf(NotFoundException.class);

    assertThatThrownBy(() -> kv.read("a", 1)).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.write("a", Map.of(), 1)).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.patch("a", Map.of())).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.deleteVersions("a", List.of(1)))
        .isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.undelete("a", List.of(1))).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.destroy("a", List.of(1))).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.readMetadata("a")).isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(
            () -> kv.writeMetadata("a", KvMetadataOptions.builder().maxVersions(1).build()))
        .isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> kv.deleteMetadata("a")).isInstanceOf(UnsupportedException.class);
    assertThat(server.requests()).hasSize(6);
  }

  @Test
  void v1PatchOnServerIs405Unsupported() {
    enqueue(server, "kvV1.patch.unsupported");
    assertThatThrownBy(() -> client.request("PATCH", "kv1/x", Map.of("a", "3")))
        .isInstanceOf(UnsupportedException.class);
  }

  @Test
  void mountDetectsVersionOnce() {
    KvMount kv = client.kv();
    assertThat(client.kv("secret/")).isSameAs(kv);
    assertThat(kv.mount()).isEqualTo("secret");
    assertThat(kv.toString()).isEqualTo("KvMount(secret)");
    enqueue(server, "mountDetect.kv2");
    enqueue(server, "kvV2.read.ok");
    assertThat(kv.read("sdk/allowed/hello").data()).containsKey("a");
    assertThat(server.requests().get(0).uri())
        .isEqualTo("/v1/sys/internal/ui/mounts/secret/sdk/allowed/hello");
    assertThat(kv.version()).isEqualTo(2);
    assertThat(kv.engine()).isInstanceOf(KvV2.class);
    // every call delegates without a second detection
    enqueue(server, "kvV2.write.no-options");
    kv.write("a", Map.of("v", "b"));
    enqueue(server, "kvV2.write.cas-ok");
    kv.write("a", Map.of("v", "b"), 1);
    enqueue(server, "kvV2.patch.ok");
    kv.patch("a", Map.of("v", "c"));
    enqueue(server, "kvV2.patch.ok");
    kv.patch("a", Map.of("v", "c"), 2);
    enqueue(server, "kvV2.read.version");
    kv.read("a", 1);
    enqueue(server, "kvV2.delete.ok");
    kv.delete("a");
    enqueue(server, "kvV2.deleteVersions.ok");
    kv.deleteVersions("a", List.of(1));
    enqueue(server, "kvV2.undelete.ok");
    kv.undelete("a", List.of(1));
    enqueue(server, "kvV2.destroy.ok");
    kv.destroy("a", List.of(1));
    enqueue(server, "kvV2.list.ok");
    kv.list("");
    enqueue(server, "kvV2.list.ok");
    kv.list("", "a", 2);
    enqueue(server, "kvV2.readMetadata.ok");
    kv.readMetadata("a");
    enqueue(server, "kvV2.writeMetadata.ok");
    kv.writeMetadata("a", KvMetadataOptions.builder().casRequired(true).build());
    enqueue(server, "kvV2.deleteMetadata.ok");
    kv.deleteMetadata("a");
    assertThat(server.requests()).hasSize(16);
    assertThat(
            server.requests().stream().filter(r -> r.uri().contains("internal/ui/mounts")).count())
        .isEqualTo(1);
  }

  @Test
  void mountDetection() {
    enqueue(server, "mountDetect.kv1");
    assertThat(client.kv("kv1").version()).isEqualTo(1);
    // no options -> version 1
    server.enqueue(200, "{\"data\":{\"type\":\"kv\",\"options\":null}}");
    assertThat(client.kv("old").version()).isEqualTo(1);
    server.enqueue(200, "{\"data\":{\"type\":\"transit\"}}");
    assertThatThrownBy(() -> client.kv("transit").version())
        .isInstanceOf(ValidationException.class)
        .hasMessageContaining("not a KV mount");
    server.enqueue(200, "{\"data\":{\"type\":\"kv\",\"options\":{\"version\":\"3\"}}}");
    assertThatThrownBy(() -> client.kv("weird").version()).isInstanceOf(UnavailableException.class);
    // a failed detection is retried on the next call
    enqueue(server, "mountDetect.no-access");
    KvMount m = client.kv("secret");
    assertThatThrownBy(m::version).isInstanceOf(PermissionDeniedException.class);
    enqueue(server, "mountDetect.kv2");
    assertThat(m.version()).isEqualTo(2);
  }

  @Test
  void fixedVersionSkipsDetection() {
    try (OpenBaoClient c = Fixtures.client(server).kvVersion(1).kvMount("kv1").build()) {
      enqueue(server, "kvV1.read.ok");
      assertThat(c.kv().read("a").data()).containsKey("a");
      assertThat(c.kv().version()).isEqualTo(1);
      assertThat(server.requests()).hasSize(1);
    }
  }
}
