package network.crypta.apps.mail;

import java.util.Map;

/**
 * Authenticated local platform transport used by the worker; test implementations own isolated
 * stores.
 */
@FunctionalInterface
public interface MailBackend {
  /**
   * Performs one worker-selected Platform API request over the authenticated local transport.
   *
   * @param method HTTP method required by the fixed endpoint
   * @param path relative Platform API path, beginning with a slash
   * @param parameters bounded form or query parameters; may contain private endpoint data
   * @return parsed response object; no raw response is logged by this interface
   */
  Map<String, Object> request(String method, String path, Map<String, String> parameters);
}
