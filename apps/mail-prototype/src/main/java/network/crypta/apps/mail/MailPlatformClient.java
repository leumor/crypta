package network.crypta.apps.mail;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Bounded synchronous HTTP client for the AppHost-selected loopback Platform API.
 *
 * <p>The launch token is sent only in the process authentication header. The endpoint must use an
 * explicit port and the {@code /api/v1} mount on literal {@code 127.0.0.1} or {@code ::1};
 * redirects are disabled. Connection setup is bounded to five seconds and each HTTP request has a
 * 25-second timeout. Form and response byte caps are enforced separately.
 *
 * <p>Responses may contain private plaintext and are returned only to the worker. Ordinary failure
 * responses are mapped to fixed codes without retaining remote error text. Interrupted requests
 * restore the thread's interrupt flag and raise a bounded unavailable failure.
 */
final class MailPlatformClient implements MailBackend {
  /** Validated literal loopback Platform API mount. */
  private final URI endpoint;

  /** Private launch credential, never returned to the browser. */
  private final String token;

  /** HTTP client that never follows redirects and uses a bounded connection timeout. */
  private final HttpClient client =
      HttpClient.newBuilder()
          .connectTimeout(Duration.ofSeconds(5))
          .followRedirects(HttpClient.Redirect.NEVER)
          .build();

  /**
   * Connects only to the AppHost-selected literal loopback API endpoint.
   *
   * @param endpoint HTTP loopback URI ending exactly at the API v1 mount
   * @param token private current-process credential supplied by the launch environment
   * @throws IllegalArgumentException if the endpoint or token shape is invalid
   */
  MailPlatformClient(String endpoint, String token) {
    this.endpoint = URI.create(endpoint);
    this.token = token;
    if (!"http".equals(this.endpoint.getScheme())
        || !java.util.List.of("127.0.0.1", "[::1]", "::1").contains(this.endpoint.getHost())
        || !"/api/v1".equals(this.endpoint.getPath())
        || this.endpoint.getPort() < 1
        || this.endpoint.getQuery() != null
        || this.endpoint.getFragment() != null
        || this.endpoint.getUserInfo() != null
        || token == null
        || token.isBlank()) throw new IllegalArgumentException("Mail endpoint unavailable.");
  }

  @Override
  public Map<String, Object> request(String method, String path, Map<String, String> parameters) {
    if (!path.startsWith("/") || path.contains("..") || path.contains("?") || path.contains("#"))
      throw new IllegalArgumentException();
    String form =
        parameters.entrySet().stream()
            .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
            .collect(Collectors.joining("&"));
    if (form.length() > 786432) throw new MailFailure("quota");
    URI uri =
        URI.create(
            endpoint.toString()
                + path
                + ("GET".equals(method) && !form.isEmpty() ? "?" + form : ""));
    var request =
        HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(25))
            .header("X-Crypta-App-Token", token);
    if ("GET".equals(method)) request.GET();
    else
      request
          .header("Content-Type", "application/x-www-form-urlencoded")
          .method(method, HttpRequest.BodyPublishers.ofString(form));
    try {
      var response = client.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
      return readResponse(response);
    } catch (java.io.IOException _) {
      throw new MailFailure("network-failed");
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
      throw new MailFailure("unavailable");
    }
  }

  /**
   * Reads and closes a bounded response before interpreting its status and complete JSON body.
   *
   * @param response received response whose body is consumed and closed here
   * @return parsed object for a successful HTTP status
   * @throws java.io.IOException if reading or closing the response body fails
   * @throws MailFailure if the body exceeds 1 MiB or the response indicates an operation failure
   */
  private static Map<String, Object> readResponse(HttpResponse<java.io.InputStream> response)
      throws java.io.IOException {
    byte[] bytes;
    try (var body = response.body()) {
      bytes = body.readNBytes(1048577);
    }
    if (bytes.length > 1048576) throw new MailFailure("quota");
    if (response.statusCode() < 200 || response.statusCode() >= 300)
      throw responseFailure(response.statusCode(), bytes);
    return object(MailApiJsonParser.parse(new String(bytes, StandardCharsets.UTF_8)));
  }

  /**
   * Maps only allowlisted error codes or HTTP statuses to private, bounded failure messages.
   *
   * @param statusCode unsuccessful HTTP status code
   * @param bytes complete bounded error response body
   * @return fixed local failure, giving recognized structured codes precedence over HTTP status
   */
  private static MailFailure responseFailure(int statusCode, byte[] bytes) {
    Object code = errorCode(bytes);
    if ("key_unavailable".equals(code) || "mail_identity_denied".equals(code))
      return new MailFailure("key-unavailable");
    if ("mail_operation_rejected".equals(code)) return new MailFailure("invalid");
    if ("app_data_write_conflict".equals(code)) return new MailFailure("state-conflict");
    if ("app_data_quota_exceeded".equals(code)) return new MailFailure("quota");
    return switch (statusCode) {
      case 404 -> new MailFailure("not-found");
      case 401, 403 -> new MailFailure("key-unavailable");
      default -> new MailFailure("platform-unavailable");
    };
  }

  /**
   * Extracts an error code without exposing malformed response text or parser diagnostics.
   *
   * @param bytes complete bounded error response body
   * @return the untrusted code value, or null if absent or malformed; callers must allowlist it
   */
  private static Object errorCode(byte[] bytes) {
    try {
      Object parsed = MailApiJsonParser.parse(new String(bytes, StandardCharsets.UTF_8));
      Object error = parsed instanceof Map<?, ?> root ? root.get("error") : null;
      return error instanceof Map<?, ?> details ? details.get("code") : null;
    } catch (IllegalArgumentException _) {
      return null;
    }
  }

  /**
   * Requires the expected object shape after bounded JSON parsing.
   *
   * @param value parsed local response value
   * @return string-keyed object supplied by the local JSON parser
   * @throws MailFailure if the value is not an object
   */
  @SuppressWarnings("unchecked")
  static Map<String, Object> object(Object value) {
    if (!(value instanceof Map<?, ?>)) throw new MailFailure("invalid");
    return (Map<String, Object>) value;
  }

  /**
   * Encodes one UTF-8 form parameter.
   *
   * @param value encoded or parsed input value
   * @return UTF-8 form-encoded text
   */
  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}
