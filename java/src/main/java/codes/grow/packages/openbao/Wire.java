package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.EnvReader;
import codes.grow.packages.openbao.core.HttpTransport;
import codes.grow.packages.openbao.core.Json;
import codes.grow.packages.openbao.core.NotFoundException;
import codes.grow.packages.openbao.core.OpenBaoException;
import codes.grow.packages.openbao.core.Secret;
import codes.grow.packages.openbao.core.UnavailableException;
import codes.grow.packages.openbao.core.ValidationException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Supplier;

/** Wire helpers shared by the service modules (paths, durations, JSON field access). */
final class Wire {
  private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {};

  private Wire() {}

  /**
   * Strips leading and trailing slashes.
   *
   * @param value text
   * @return the trimmed text
   */
  static String trimSlashes(String value) {
    return value.replaceAll("^/+|/+$", "");
  }

  /**
   * Joins path parts with {@code /} and percent-encodes each segment, keeping the separators. Empty
   * segments are skipped: {@code encodePath("kv1", "sdk/with space")} is {@code
   * kv1/sdk/with%20space}.
   *
   * @param parts path parts
   * @return the encoded path
   */
  static String encodePath(String... parts) {
    StringBuilder sb = new StringBuilder();
    for (String part : parts) {
      for (String seg : part.split("/")) {
        if (seg.isEmpty()) {
          continue;
        }
        if (sb.length() > 0) {
          sb.append('/');
        }
        sb.append(URLEncoder.encode(seg, StandardCharsets.UTF_8).replace("+", "%20"));
      }
    }
    return sb.toString();
  }

  /**
   * Joins two path parts with one {@code /} (no encoding).
   *
   * @param base base path, may be empty
   * @param name name, may be empty
   * @return the joined path
   */
  static String join(String base, String name) {
    String b = trimSlashes(base);
    String n = trimSlashes(name);
    if (b.isEmpty()) {
      return n;
    }
    return n.isEmpty() ? b : b + "/" + n;
  }

  /**
   * Rejects empty text client side.
   *
   * @param value value to check
   * @param what field name for the message
   * @param operation operation name
   * @return the value
   * @throws ValidationException when the value is null or blank
   */
  static String requireText(String value, String what, String operation) {
    if (value == null || value.trim().isEmpty()) {
      throw new ValidationException(operation + ": " + what + " must not be empty");
    }
    return value;
  }

  /**
   * Formats a duration as whole seconds for OpenBao, rounded up ({@code 1500 ms} is {@code 2s}).
   *
   * @param d non-negative duration
   * @return e.g. {@code 30s}
   * @throws ValidationException when the duration is negative
   */
  static String duration(Duration d) {
    if (d.isNegative()) {
      throw new ValidationException("invalid duration: must not be negative");
    }
    long seconds = d.getSeconds() + (d.getNano() > 0 ? 1 : 0);
    return seconds + "s";
  }

  /**
   * {@link #duration(Duration)} or null.
   *
   * @param d duration, may be null
   * @return the text or null
   */
  static String optDuration(Duration d) {
    return d == null ? null : duration(d);
  }

  /**
   * Seconds (wire) to a duration; non-numbers are zero.
   *
   * @param node JSON value
   * @return the duration
   */
  static Duration seconds(JsonNode node) {
    return node != null && node.isNumber() ? Duration.ofSeconds(node.asLong()) : Duration.ZERO;
  }

  /**
   * Parses an OpenBao duration value: seconds as a number or a Go duration string such as {@code
   * 720h0m0s}.
   *
   * @param node JSON value
   * @return the duration, zero when absent or invalid
   */
  static Duration vaultDuration(JsonNode node) {
    if (node == null || node.isNull()) {
      return Duration.ZERO;
    }
    if (node.isNumber()) {
      return Duration.ofSeconds(node.asLong());
    }
    String s = node.asText();
    if (s.chars().allMatch(Character::isDigit) && !s.isEmpty()) {
      return Duration.ofSeconds(Long.parseLong(s));
    }
    return EnvReader.parseDuration(s).orElse(Duration.ZERO);
  }

  /**
   * Parses a timestamp: RFC 3339 text or unix seconds. Empty, zero and invalid values are empty.
   *
   * @param node JSON value
   * @return the instant, or empty
   */
  static Optional<Instant> time(JsonNode node) {
    if (node == null || node.isNull()) {
      return Optional.empty();
    }
    if (node.isNumber()) {
      long s = node.asLong();
      return s > 0 ? Optional.of(Instant.ofEpochSecond(s)) : Optional.empty();
    }
    String text = node.asText();
    if (text.isEmpty()) {
      return Optional.empty();
    }
    try {
      return Optional.of(Instant.parse(text));
    } catch (DateTimeParseException e) {
      return Optional.empty();
    }
  }

  /**
   * Text of a field, {@code ""} when absent or not text.
   *
   * @param node object, may be null
   * @param field field name
   * @return the text
   */
  static String str(JsonNode node, String field) {
    JsonNode v = node == null ? null : node.get(field);
    return v != null && v.isTextual() ? v.asText() : "";
  }

  /**
   * Integer field, 0 when absent.
   *
   * @param node object, may be null
   * @param field field name
   * @return the number
   */
  static int num(JsonNode node, String field) {
    JsonNode v = node == null ? null : node.get(field);
    return v != null && v.isNumber() ? v.asInt() : 0;
  }

  /**
   * Boolean field, true only for JSON {@code true}.
   *
   * @param node object, may be null
   * @param field field name
   * @return the flag
   */
  static boolean bool(JsonNode node, String field) {
    JsonNode v = node == null ? null : node.get(field);
    return v != null && v.isBoolean() && v.asBoolean();
  }

  /**
   * String list from an array (other values give an empty list).
   *
   * @param node array, may be null
   * @return immutable list
   */
  static List<String> strings(JsonNode node) {
    List<String> out = new ArrayList<>();
    if (node != null && node.isArray()) {
      for (JsonNode n : node) {
        if (n.isTextual()) {
          out.add(n.asText());
        }
      }
    }
    return List.copyOf(out);
  }

  /**
   * String map from an object; non-string values are JSON-encoded, nulls skipped.
   *
   * @param node object, may be null
   * @return immutable map (insertion order kept)
   */
  static Map<String, String> stringMap(JsonNode node) {
    Map<String, String> out = new LinkedHashMap<>();
    if (node != null && node.isObject()) {
      for (Map.Entry<String, JsonNode> e : node.properties()) {
        JsonNode v = e.getValue();
        if (v.isNull()) {
          continue;
        }
        out.put(e.getKey(), v.isTextual() ? v.asText() : Json.stringify(v));
      }
    }
    return java.util.Collections.unmodifiableMap(out);
  }

  /**
   * Converts a JSON object into a plain map.
   *
   * @param node object
   * @return mutable map of plain Java values
   */
  static Map<String, Object> toMap(JsonNode node) {
    return Json.mapper().convertValue(node, MAP);
  }

  /**
   * Standard base64 of bytes.
   *
   * @param value bytes
   * @return base64 text
   */
  static String b64(byte[] value) {
    return Base64.getEncoder().encodeToString(value);
  }

  /**
   * Base64 of bytes or null.
   *
   * @param value bytes, may be null
   * @return base64 text or null
   */
  static String optB64(byte[] value) {
    return value == null ? null : b64(value);
  }

  /**
   * Decodes standard base64.
   *
   * @param value base64 text
   * @param operation operation name for errors
   * @return the bytes
   * @throws UnavailableException when the text is not base64
   */
  static byte[] unb64(String value, String operation) {
    try {
      return Base64.getDecoder().decode(value);
    } catch (IllegalArgumentException e) {
      throw unexpected(operation, "invalid base64");
    }
  }

  /**
   * A secret for a non-empty text field.
   *
   * @param node object
   * @param field field name
   * @return the secret, or empty
   */
  static Optional<Secret> optSecret(JsonNode node, String field) {
    String s = str(node, field);
    return s.isEmpty() ? Optional.empty() : Optional.of(Secret.of(s));
  }

  /**
   * Error for a response that does not have the documented shape (not retryable).
   *
   * @param operation operation name
   * @param reason short reason
   * @return the exception
   */
  static UnavailableException unexpected(String operation, String reason) {
    return new UnavailableException(operation + ": unexpected response (" + reason + ")");
  }

  /**
   * Runs a future-producing step, turning a synchronous exception into a failed future.
   *
   * @param <T> result type
   * @param step the step
   * @return the future
   */
  static <T> CompletableFuture<T> async(Supplier<CompletableFuture<T>> step) {
    try {
      return step.get();
    } catch (RuntimeException e) {
      return CompletableFuture.failedFuture(e);
    }
  }

  /**
   * Maps a {@code NotFoundException} to a fallback value.
   *
   * @param <T> result type
   * @param f the future
   * @param fallback value for not found
   * @return the future with the fallback applied
   */
  static <T> CompletableFuture<T> orElseOnNotFound(CompletableFuture<T> f, T fallback) {
    return f.handle(
        (v, t) -> {
          if (t == null) {
            return v;
          }
          OpenBaoException e = HttpTransport.asSdkException(t, "notFound");
          if (e instanceof NotFoundException) {
            return fallback;
          }
          throw new CompletionException(e);
        });
  }

  /** Fluent map builder that skips null values. */
  static final class Body {
    private final Map<String, Object> map = new LinkedHashMap<>();

    Body put(String key, Object value) {
      if (value != null) {
        map.put(key, value);
      }
      return this;
    }

    Map<String, Object> build() {
      return map;
    }
  }

  static Body body() {
    return new Body();
  }
}
