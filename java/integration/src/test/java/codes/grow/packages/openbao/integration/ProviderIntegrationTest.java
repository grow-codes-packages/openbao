package codes.grow.packages.openbao.integration;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.openbao.OpenBaoClient;
import codes.grow.packages.openbao.OpenBaoSecretsProvider;
import codes.grow.packages.openbao.SecretsOptions;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.UnsupportedException;
import codes.grow.packages.openbao.secrets.DeleteOptions;
import codes.grow.packages.openbao.secrets.GetOptions;
import codes.grow.packages.openbao.secrets.SecretMetadata;
import codes.grow.packages.openbao.secrets.SetOptions;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class ProviderIntegrationTest {
  @Test
  void kvV2Provider() {
    Map<String, String> env = Env.load();
    String base = "sdk/java-provider/" + Env.run();
    try (OpenBaoClient c = Env.root(env)) {
      OpenBaoSecretsProvider p = c.secrets(SecretsOptions.builder().path(base).build());
      assertEquals("1", p.set("db", "s3cret"));
      assertEquals("2", p.set("db", "s3cret-2", SetOptions.builder().cas(1).tag("owner", "sdk").build()));
      assertEquals("s3cret-2", p.get("db").get().reveal());
      assertEquals("s3cret", p.get("db", GetOptions.builder().version("1").build()).get().reveal());
      byte[] bin = {(byte) 0xff, 0, 7};
      p.set("bin", bin);
      assertArrayEquals(bin, p.get("bin").get().revealBytes());
      assertEquals("base64", c.kv().read(base + "/bin").data().get("encoding"));
      p.set("obj", Map.of("a", 1));
      assertEquals(1, p.getJson("obj", JsonNode.class).get().get("a").asInt());
      SecretMetadata m = p.metadata("db").get();
      assertEquals("2", m.version().get());
      assertEquals("sdk", m.tags().get("owner"));
      List<String> names = p.list("").stream().map(SecretMetadata::name).collect(Collectors.toList());
      assertEquals(List.of("bin", "db", "obj"), names);
      assertEquals(3, p.getAll("").size());
      p.delete("db", DeleteOptions.builder().versions("1").build());
      p.delete("db");
      assertTrue(p.get("db").isEmpty());
      assertThrows(NotFoundException.class, () -> p.delete("db"));
      p.delete("db", DeleteOptions.builder().permanent(true).build());
      p.delete("bin", DeleteOptions.builder().permanent(true).build());
      p.delete("obj", DeleteOptions.builder().permanent(true).build());
      assertTrue(p.list("").isEmpty());
    }
  }

  @Test
  void kvV1Provider() {
    Map<String, String> env = Env.load();
    String base = "sdk/java-provider/" + Env.run();
    try (OpenBaoClient c = Env.root(env)) {
      OpenBaoSecretsProvider p =
          c.secrets(SecretsOptions.builder().mount(Env.get(env, "KV1_MOUNT")).path(base).build());
      assertEquals("", p.set("one", "1"));
      assertEquals("1", p.require("one").reveal());
      assertTrue(p.get("one").get().version().isEmpty());
      assertThrows(UnsupportedException.class, () -> p.set("one", "x", SetOptions.builder().cas(0).build()));
      assertEquals(List.of("one"), p.list("").stream().map(SecretMetadata::name).collect(Collectors.toList()));
      assertTrue(p.metadata("one").isPresent());
      p.delete("one");
      assertFalse(p.exists("one"));
      assertThrows(NotFoundException.class, () -> p.delete("one"));
    }
  }
}
