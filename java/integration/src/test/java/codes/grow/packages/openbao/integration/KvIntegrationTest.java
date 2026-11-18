package codes.grow.packages.openbao.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.openbao.KvMetadata;
import codes.grow.packages.openbao.KvMetadataOptions;
import codes.grow.packages.openbao.KvMount;
import codes.grow.packages.openbao.KvSecret;
import codes.grow.packages.openbao.KvV1;
import codes.grow.packages.openbao.KvV2;
import codes.grow.packages.openbao.KvVersionMetadata;
import codes.grow.packages.openbao.OpenBaoClient;
import codes.grow.packages.openbao.core.ConflictException;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.UnsupportedException;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class KvIntegrationTest {
  @Test
  void kvV2() {
    Map<String, String> env = Env.load();
    String base = "sdk/java/" + Env.run();
    try (OpenBaoClient c = Env.root(env)) {
      KvMount mount = c.kv(Env.get(env, "KV2_MOUNT"));
      assertEquals(2, mount.version());
      KvV2 kv = c.kvV2(Env.get(env, "KV2_MOUNT"));
      String p = base + "/alpha";
      KvVersionMetadata v1 = kv.write(p, Map.of("a", "1", "b", "2")).get();
      assertEquals(1, v1.version());
      KvSecret read = mount.read(p);
      assertEquals("1", read.data().get("a"));
      assertEquals(1, read.metadata().get().version());
      assertThrows(ConflictException.class, () -> kv.write(p, Map.of("a", "x"), 0));
      assertEquals(2, kv.write(p, Map.of("a", "2"), 1).get().version());
      Map<String, Object> patch = new HashMap<>();
      patch.put("c", "3");
      patch.put("a", null);
      assertEquals(3, kv.patch(p, patch).version());
      KvSecret patched = kv.read(p);
      assertEquals("3", patched.data().get("c"));
      assertFalse(patched.data().containsKey("a"));
      assertEquals(4, kv.patch(p, Map.of("d", 4), 3).version());
      assertEquals("1", kv.read(p, 1).data().get("a"));
      kv.write(base + "/beta", Map.of("v", "b"));
      kv.write(base + "/dir/gamma", Map.of("v", "g"));
      assertEquals(List.of("alpha", "beta", "dir/"), kv.list(base));
      assertEquals(List.of("beta"), kv.list(base, "alpha", 1));
      assertTrue(kv.list(base + "/missing").isEmpty());

      kv.writeMetadata(
          p,
          KvMetadataOptions.builder()
              .maxVersions(10)
              .casRequired(false)
              .deleteVersionAfter(Duration.ofHours(720))
              .customMetadata(Map.of("owner", "sdk"))
              .build());
      KvMetadata meta = kv.readMetadata(p);
      assertEquals(4, meta.currentVersion());
      assertEquals(10, meta.maxVersions());
      assertEquals(Duration.ofHours(720), meta.deleteVersionAfter());
      assertEquals("sdk", meta.customMetadata().get("owner"));
      assertEquals(4, meta.versions().size());

      kv.deleteVersions(p, List.of(1));
      assertThrows(NotFoundException.class, () -> kv.read(p, 1));
      kv.undelete(p, List.of(1));
      assertEquals("1", kv.read(p, 1).data().get("a"));
      kv.destroy(p, List.of(1));
      assertThrows(NotFoundException.class, () -> kv.read(p, 1));
      assertTrue(kv.readMetadata(p).versions().get(1).destroyed());
      kv.delete(p);
      assertThrows(NotFoundException.class, () -> kv.read(p));
      assertTrue(kv.readMetadata(p).currentDeleted());
      kv.deleteMetadata(p);
      assertThrows(NotFoundException.class, () -> kv.readMetadata(p));
      assertFalse(kv.list(base).contains("alpha"));
      kv.deleteMetadata(base + "/beta");
      kv.deleteMetadata(base + "/dir/gamma");
      // percent-encoded segments
      kv.write(base + "/with space", Map.of("v", "s"));
      assertEquals("s", kv.read(base + "/with space").data().get("v"));
      kv.deleteMetadata(base + "/with space");
    }
  }

  @Test
  void kvV1() {
    Map<String, String> env = Env.load();
    String base = "sdk/java/" + Env.run();
    try (OpenBaoClient c = Env.root(env)) {
      KvMount mount = c.kv(Env.get(env, "KV1_MOUNT"));
      assertEquals(1, mount.version());
      KvV1 kv = c.kvV1(Env.get(env, "KV1_MOUNT"));
      assertTrue(kv.write(base + "/a", Map.of("x", "1", "n", 2)).isEmpty());
      assertEquals(2, ((Number) kv.read(base + "/a").data().get("n")).intValue());
      kv.write(base + "/a", Map.of("x", "2"));
      assertFalse(mount.read(base + "/a").data().containsKey("n"));
      assertEquals(List.of("a"), mount.list(base));
      assertThrows(UnsupportedException.class, () -> mount.patch(base + "/a", Map.of("y", 1)));
      assertThrows(UnsupportedException.class, () -> mount.readMetadata(base + "/a"));
      kv.delete(base + "/a");
      assertThrows(NotFoundException.class, () -> kv.read(base + "/a"));
      kv.delete(base + "/a"); // missing path: no error
    }
  }

  @Test
  void namespace() {
    Map<String, String> env = Env.load();
    String ns = Env.get(env, "NAMESPACE");
    if (ns.isEmpty()) {
      return;
    }
    try (OpenBaoClient c =
        OpenBaoClient.builder()
            .url(env.get("GROW_OPENBAO_URL"))
            .token(env.get("GROW_OPENBAO_TOKEN"))
            .namespace(ns)
            .build()) {
      assertEquals("ns-only", c.kv().read("sdk/in-namespace").data().get("value"));
    }
    try (OpenBaoClient root = Env.root(env)) {
      assertThrows(NotFoundException.class, () -> root.kvV2("secret").read("sdk/in-namespace"));
    }
  }
}
