package network.crypta.apps.mail;

import java.util.Map;

/**
 * Synchronous platform transport used by the worker for fixed Mail, app-data and CHK operations.
 *
 * <p>Production requests use the current AppHost process credential over the host-selected loopback
 * API. Implementations must preserve that authority boundary and avoid logging request/response
 * contents. The mailbox serializes its calls; this interface does not require implementations to
 * support concurrent requests. Test implementations may provide isolated stores and simulated
 * network transport without establishing live-network evidence.
 */
@FunctionalInterface
public interface MailBackend {
  /**
   * Performs one worker-selected Platform API request over the authenticated local transport.
   *
   * @param method HTTP method required by the fixed endpoint
   * @param path path relative to the configured API mount, beginning with a slash; not a URL
   * @param parameters non-null string-valued form or query fields, potentially containing private
   *     data
   * @return parsed response object whose shape must still be validated by the caller
   * @throws RuntimeException if transport, authorization, parameter or response validation fails;
   *     the production implementation uses bounded failure codes for ordinary operation failures
   */
  Map<String, Object> request(String method, String path, Map<String, String> parameters);
}
