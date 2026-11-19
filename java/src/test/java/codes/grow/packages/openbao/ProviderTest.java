package codes.grow.packages.openbao;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.UnsupportedException;
import codes.grow.packages.openbao.core.ValidationException;
import codes.grow.packages.openbao.secrets.DeleteOptions;
import codes.grow.packages.openbao.secrets.GetOptions;
import codes.grow.packages.openbao.secrets.SecretMetadata;
import codes.grow.packages.openbao.secrets.SetOptions;
import codes.grow.packages.openbao.testing.ConformanceReport;
import codes.grow.packages.openbao.testing.ConformanceRunner;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ProviderTest {
  private FakeKvServer server;
  private OpenBaoClient client;

  @BeforeEach
  void start() throws Exception {
    server = new FakeKvServer();
    client = OpenBaoClient.builder().url(server.url()).token("root-token-1234").build();
  }

  @AfterEach
  void stop() {
    client.close();
    server.close();
  }

  @Test
  void v2RoundTrip() {
    OpenBaoSecretsProvider p = client.secrets(SecretsOptions.builder().path("app").build());
    assertThat(p.kv().mount()).isEqualTo("secret");
    assertThat(p.fullPath("db", null)).isEqualTo("app/db");
    assertThat(p.fullPath("db", "other/")).isEqualTo("other/db");
    assertThat(p.toString()).isEqualTo("OpenBaoSecretsProvider(secret/app)");
    assertThat(p.set("db", "s3cret")).isEqualTo("1");
    assertThat(p.set("db", "s3cret-2", SetOptions.builder().cas(1).tag("owner", "sdk").build()))
        .isEqualTo("2");
    assertThat(p.get("db").get().reveal()).isEqualTo("s3cret-2");
    assertThat(p.get("db").get().version()).contains("2");
    assertThat(p.get("db", GetOptions.builder().version("1").build()).get().reveal())
        .isEqualTo("s3cret");
    assertThatThrownBy(() -> p.get("db", GetOptions.builder().version("x").build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> p.get("db", GetOptions.builder().version("0").build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> p.set("db", "v", SetOptions.builder().cas(1).build()))
        .isInstanceOf(codes.grow.packages.openbao.core.ConflictException.class);
    // bytes and objects
    byte[] bin = {(byte) 0xff, 0, 1};
    p.set("bin", bin);
    assertThat(p.get("bin").get().revealBytes()).isEqualTo(bin);
    p.set("obj", Map.of("a", 1));
    assertThat(p.getJson("obj", JsonNode.class).get().get("a").asInt()).isEqualTo(1);
    // a multi-field secret without "value" reads as JSON of the map
    client.kv().write("app/multi", Map.of("user", "u", "pass", "p"));
    assertThat(p.getJson("multi", JsonNode.class).get().get("user").asText()).isEqualTo("u");
    // non-string value field
    client.kv().write("app/num", Map.of("value", 42));
    assertThat(p.getNumber("num")).contains(42.0);
    client.kv().write("app/badb64", Map.of("value", "***", "encoding", "base64"));
    assertThatThrownBy(() -> p.get("badb64")).isInstanceOf(ValidationException.class);
    client.kv().deleteMetadata("app/badb64");

    SecretMetadata m = p.metadata("db").get();
    assertThat(m.version()).contains("2");
    assertThat(m.path()).contains("app");
    assertThat(m.tags()).containsEntry("owner", "sdk");
    assertThat(m.versions()).hasValue(2);
    assertThat(m.createdAt()).isPresent();
    assertThat(m.updatedAt()).isPresent();
    assertThat(m.extra())
        .containsKeys("maxVersions", "casRequired", "deleteVersionAfter", "oldestVersion");
    assertThat(m.extra().get("deleteVersionAfter")).endsWith("s");
    assertThat(p.metadata("missing")).isEmpty();

    List<SecretMetadata> list = p.list("");
    assertThat(list).extracting(SecretMetadata::name).contains("db", "bin", "obj");
    assertThat(p.getAll("")).containsKeys("db", "bin");

    // delete variants
    p.delete("db", DeleteOptions.builder().versions("1").build());
    assertThat(p.get("db").get().version()).contains("2");
    assertThatThrownBy(() -> p.delete("db", DeleteOptions.builder().versions("x").build()))
        .isInstanceOf(ValidationException.class);
    p.delete("db");
    assertThat(p.get("db")).isEmpty();
    assertThat(p.metadata("db")).isEmpty();
    assertThat(p.list("")).extracting(SecretMetadata::name).doesNotContain("db");
    assertThatThrownBy(() -> p.delete("db")).isInstanceOf(NotFoundException.class);
    p.delete("obj", DeleteOptions.builder().permanent(true).build());
    assertThat(p.exists("obj")).isFalse();
    assertThatThrownBy(() -> p.delete("obj", DeleteOptions.builder().permanent(true).build()))
        .isInstanceOf(NotFoundException.class);
    assertThat(p.list("nothing-here")).isEmpty();
    p.close();
    p.close();
  }

  @Test
  void v1Provider() {
    OpenBaoSecretsProvider p =
        client.secrets(SecretsOptions.builder().mount("kv1").valueField("v").build());
    assertThat(p.set("a/one", "1")).isEmpty();
    assertThat(p.get("a/one").get().reveal()).isEqualTo("1");
    assertThat(p.get("a/one").get().version()).isEmpty();
    assertThatThrownBy(() -> p.get("a/one", GetOptions.builder().version("1").build()))
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> p.set("a/one", "x", SetOptions.builder().cas(0).build()))
        .isInstanceOf(UnsupportedException.class);
    assertThatThrownBy(() -> p.set("a/one", "x", SetOptions.builder().tag("k", "v").build()))
        .isInstanceOf(UnsupportedException.class);
    p.set("a/two", "2");
    assertThat(p.list("a")).extracting(SecretMetadata::name).containsExactly("a/one", "a/two");
    assertThat(p.list("a").get(0).version()).isEmpty();
    assertThat(p.metadata("a/one").get().path()).contains("a");
    assertThat(p.metadata("zzz")).isEmpty();
    assertThat(p.metadata("top")).isEmpty();
    p.set("top", "t");
    assertThat(p.metadata("top").get().path()).isEmpty();
    p.delete("a/one");
    assertThatThrownBy(() -> p.delete("a/one")).isInstanceOf(NotFoundException.class);
  }

  @Test
  void conformanceAgainstFakeServer() {
    Path dir = Paths.get("..", "conformance", "scenarios");
    ConformanceReport report =
        ConformanceRunner.builder()
            .scenarioDir(dir)
            .capabilities(OpenBaoSecretsProvider.CAPABILITIES.toArray(new String[0]))
            .target("secrets", scenario -> client.secrets())
            .build()
            .run();
    report.assertPassed();
  }
}
