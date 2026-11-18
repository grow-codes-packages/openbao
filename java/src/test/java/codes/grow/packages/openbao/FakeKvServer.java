package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Json;
import codes.grow.packages.openbao.core.MockServer;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * A tiny in-memory OpenBao KV server for provider and conformance unit tests: mount {@code kv1} is
 * KV v1, every other mount KV v2. Behaviour follows the recorded fixtures (204 for deletes of
 * missing paths, 404 for empty lists).
 */
final class FakeKvServer implements AutoCloseable {
  private final HttpServer http;
  private final Map<String, Map<String, Object>> v1 = new TreeMap<>();
  private final Map<String, List<Map<String, Object>>> v2 = new TreeMap<>();
  private final Map<String, List<Boolean>> v2Deleted = new TreeMap<>();
  private final Map<String, Map<String, String>> v2Meta = new TreeMap<>();

  FakeKvServer() throws java.io.IOException {
    http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    http.createContext(
        "/",
        ex -> {
          try {
            respond(ex);
          } catch (Exception e) {
            ex.sendResponseHeaders(500, -1);
          } finally {
            ex.close();
          }
        });
    http.start();
  }

  String url() {
    return "http://127.0.0.1:" + http.getAddress().getPort();
  }

  @Override
  public void close() {
    http.stop(0);
  }

  synchronized void respond(HttpExchange ex) throws Exception {
    String raw = ex.getRequestURI().getRawPath();
    String query = ex.getRequestURI().getRawQuery();
    boolean list = query != null && query.contains("list=true");
    String path = URLDecoder.decode(raw.substring("/v1/".length()), StandardCharsets.UTF_8);
    String method = ex.getRequestMethod();
    byte[] body = ex.getRequestBody().readAllBytes();
    JsonNode json = body.length == 0 ? null : Json.tree(body);
    if (path.startsWith("sys/internal/ui/mounts/")) {
      String mount = path.substring("sys/internal/ui/mounts/".length()).split("/")[0];
      String version = mount.equals("kv1") ? "1" : "2";
      send(ex, 200, Map.of("data", Map.of("type", "kv", "options", Map.of("version", version))));
      return;
    }
    String mount = path.split("/")[0];
    String rest = path.substring(mount.length()).replaceAll("^/", "");
    if (mount.equals("kv1")) {
      v1(ex, method, rest, list, json);
    } else {
      v2(ex, method, rest, list, json, query);
    }
  }

  private void v1(HttpExchange ex, String method, String p, boolean list, JsonNode json)
      throws Exception {
    String key = p.replaceAll("/$", "");
    if (list) {
      sendKeys(ex, v1.keySet(), key);
      return;
    }
    switch (method) {
      case "GET":
        if (!v1.containsKey(key)) {
          send(ex, 404, Map.of("errors", List.of()));
        } else {
          send(ex, 200, Map.of("data", v1.get(key)));
        }
        return;
      case "POST":
      case "PUT":
        v1.put(key, Wire.toMap(json));
        send(ex, 204, null);
        return;
      default:
        v1.remove(key);
        send(ex, 204, null);
    }
  }

  private int current(String key) {
    List<Map<String, Object>> versions = v2.get(key);
    return versions == null ? 0 : versions.size();
  }

  private boolean currentDeleted(String key) {
    List<Boolean> d = v2Deleted.get(key);
    return d == null || d.isEmpty() || d.get(d.size() - 1);
  }

  private void v2(
      HttpExchange ex, String method, String p, boolean list, JsonNode json, String query)
      throws Exception {
    String kind = p.split("/")[0];
    String key = p.substring(kind.length()).replaceAll("^/|/$", "");
    switch (kind) {
      case "data":
        if (method.equals("GET")) {
          if (current(key) == 0 || currentDeleted(key)) {
            send(ex, 404, Map.of("errors", List.of()));
            return;
          }
          int version = current(key);
          if (query != null && query.startsWith("version=")) {
            version = Integer.parseInt(query.substring("version=".length()));
          }
          Map<String, Object> meta = versionMeta(key, version);
          send(
              ex,
              200,
              Map.of("data", Map.of("data", v2.get(key).get(version - 1), "metadata", meta)));
          return;
        }
        if (method.equals("DELETE")) {
          if (current(key) > 0) {
            List<Boolean> d = v2Deleted.get(key);
            d.set(d.size() - 1, true);
          }
          send(ex, 204, null);
          return;
        }
        JsonNode cas = json.path("options").path("cas");
        if (cas.isNumber() && cas.asInt() != current(key)) {
          send(
              ex,
              400,
              Map.of(
                  "errors", List.of("check-and-set parameter did not match the current version")));
          return;
        }
        v2.computeIfAbsent(key, k -> new ArrayList<>()).add(Wire.toMap(json.get("data")));
        v2Deleted.computeIfAbsent(key, k -> new ArrayList<>()).add(false);
        send(ex, 200, Map.of("data", versionMeta(key, current(key))));
        return;
      case "metadata":
        if (list) {
          sendKeys(ex, v2.keySet(), key);
          return;
        }
        if (method.equals("GET")) {
          if (current(key) == 0) {
            send(ex, 404, Map.of("errors", List.of()));
            return;
          }
          Map<String, Object> versions = new LinkedHashMap<>();
          for (int i = 1; i <= current(key); i++) {
            versions.put(String.valueOf(i), versionMeta(key, i));
          }
          Map<String, Object> d = new LinkedHashMap<>();
          d.put("current_version", current(key));
          d.put("oldest_version", 0);
          d.put("max_versions", 0);
          d.put("cas_required", false);
          d.put("delete_version_after", "0s");
          d.put("created_time", "2026-11-18T20:28:54.768226646Z");
          d.put("updated_time", "2026-11-18T20:28:56.619289639Z");
          d.put("custom_metadata", v2Meta.getOrDefault(key, Map.of()));
          d.put("versions", versions);
          send(ex, 200, Map.of("data", d));
          return;
        }
        if (method.equals("DELETE")) {
          v2.remove(key);
          v2Deleted.remove(key);
          v2Meta.remove(key);
          send(ex, 204, null);
          return;
        }
        Map<String, String> custom = new LinkedHashMap<>();
        json.path("custom_metadata")
            .properties()
            .forEach(e -> custom.put(e.getKey(), e.getValue().asText()));
        v2Meta.put(key, custom);
        send(ex, 204, null);
        return;
      case "delete":
        for (JsonNode v : json.path("versions")) {
          List<Boolean> d = v2Deleted.get(key);
          if (d != null && v.asInt() <= d.size()) {
            d.set(v.asInt() - 1, true);
          }
        }
        send(ex, 204, null);
        return;
      default:
        send(ex, 404, Map.of("errors", List.of()));
    }
  }

  private Map<String, Object> versionMeta(String key, int version) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("created_time", "2026-11-18T20:28:54.768226646Z");
    m.put("deletion_time", v2Deleted.get(key).get(version - 1) ? "2026-11-18T20:29:00Z" : "");
    m.put("destroyed", false);
    m.put("version", version);
    m.put("custom_metadata", v2Meta.get(key));
    return m;
  }

  private static void sendKeys(HttpExchange ex, Iterable<String> all, String folder)
      throws Exception {
    String prefix = folder.isEmpty() ? "" : folder + "/";
    TreeSet<String> keys = new TreeSet<>();
    for (String k : all) {
      if (k.startsWith(prefix)) {
        String rest = k.substring(prefix.length());
        int slash = rest.indexOf('/');
        keys.add(slash < 0 ? rest : rest.substring(0, slash + 1));
      }
    }
    if (keys.isEmpty()) {
      send(ex, 404, Map.of("errors", List.of()));
    } else {
      send(ex, 200, Map.of("data", Map.of("keys", new ArrayList<>(keys))));
    }
  }

  private static void send(HttpExchange ex, int status, Object body) throws Exception {
    MockServer.send(ex, status, body == null ? "" : Json.stringify(body));
  }
}
