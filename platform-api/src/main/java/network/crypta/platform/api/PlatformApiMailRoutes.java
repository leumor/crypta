package network.crypta.platform.api;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.mail.MailWorkerBroker;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppVaultService;

/** Fixed own-app mediation and process-only vault routes; no mailbox state lives here. */
final class PlatformApiMailRoutes {
  /** Authoritative current verified AppHost launch. */
  private final AppHost host;

  /** Existing purpose-scoped private identity service, when available. */
  private final AppVaultService vault;

  /** Transient private channel bound to the current verified Mail launch. */
  private final MailWorkerBroker broker;

  /**
   * Creates fixed mediation without moving mailbox state into the daemon.
   *
   * @param host current verified process lifecycle, or null when app hosting is unavailable
   * @param vault retained purpose-scoped identities, or null when vault service is unavailable
   */
  PlatformApiMailRoutes(AppHost host, AppVaultService vault) {
    this.host = host;
    this.vault = vault;
    broker = host == null ? null : new MailWorkerBroker(host);
  }

  /**
   * Routes a centrally capability-checked request after own-app and current-launch checks.
   *
   * @param request authenticated own-browser or process request with a closed parameter set
   * @return bounded private JSON response
   * @throws PlatformApiException if authorization, availability or parameter checks fail
   */
  PlatformApiResponse route(PlatformApiRequest request) {
    var principal = request.principal();
    if (!"mail-prototype".equals(principal.appId())
        || request.pathSegments().size() != 2
        || !"POST".equals(request.method())
        || broker == null) throw denied();
    String action = request.pathSegments().get(1);
    boolean browser = principal.authSource() == PlatformApiAuthSource.APP_BROWSER_SESSION;
    if (browser != List.of("command", "result").contains(action)) throw denied();
    if (!browser
        && (principal.launchId() == null
            || host.currentLaunch("mail-prototype")
                .filter(
                    p ->
                        p.launchId().equals(principal.launchId())
                            && p.permissions().equals(principal.permissions()))
                .isEmpty())) throw denied();
    java.util.Set<String> allowed =
        switch (action) {
          case "command" -> java.util.Set.of("command", "payloadBase64");
          case "result" -> java.util.Set.of("requestId");
          case "poll" -> java.util.Set.of();
          case "reply" -> java.util.Set.of("requestId", "payloadBase64");
          case "create-identity" -> java.util.Set.of("kind");
          case "sign", "open", "seal-storage", "open-storage" ->
              java.util.Set.of("identityId", "payloadBase64");
          default -> throw denied();
        };
    if (!allowed.equals(request.queryParameters().keySet())) throw denied();
    try {
      Object response =
          switch (action) {
            case "command" ->
                Map.of(
                    "requestId",
                    broker.submit(value(request, "command"), value(request, "payloadBase64")));
            case "result" -> {
              var result = broker.result(value(request, "requestId"));
              yield result
                  .<Object>map(s -> Map.of("status", "complete", "payloadBase64", s))
                  .orElse(Map.of("status", "pending"));
            }
            case "poll" -> {
              var frame = broker.poll(principal.launchId());
              yield frame
                  .<Object>map(
                      f ->
                          Map.of(
                              "requestId",
                              f.requestId(),
                              "command",
                              f.command(),
                              "payloadBase64",
                              f.payloadBase64()))
                  .orElse(Map.of("status", "idle"));
            }
            case "reply" -> {
              broker.reply(
                  principal.launchId(),
                  value(request, "requestId"),
                  value(request, "payloadBase64"));
              yield Map.of("status", "ok");
            }
            case "create-identity" -> {
              requireVault();
              var identity =
                  vault.createMailIdentity(
                      principal.appId(), AppIdentityKind.fromJsonValue(value(request, "kind")));
              yield Map.of(
                  "identityId",
                  identity.identityId(),
                  "fingerprint",
                  identity.fingerprint(),
                  "publicSummary",
                  identity.publicSummary());
            }
            case "sign", "open", "seal-storage", "open-storage" -> {
              requireVault();
              String identityId = value(request, "identityId");
              byte[] payload = payload(request);
              byte[] result =
                  switch (action) {
                    case "sign" -> vault.signMail(principal.appId(), identityId, payload);
                    case "open" -> vault.openMail(principal.appId(), identityId, payload);
                    case "seal-storage" ->
                        vault.sealStorage(principal.appId(), identityId, payload);
                    default -> vault.openStorage(principal.appId(), identityId, payload);
                  };
              yield Map.of("payloadBase64", Base64.getEncoder().encodeToString(result));
            }
            default -> throw denied();
          };
      if (!browser
          && host.currentLaunch("mail-prototype")
              .filter(p -> p.launchId().equals(principal.launchId()))
              .isEmpty()) throw denied();
      return PlatformApiResponse.ok(Map.of("mail", response));
    } catch (IllegalArgumentException exception) {
      throw new PlatformApiException(400, "mail_rejected", "Mail operation rejected.");
    } catch (IllegalStateException exception) {
      throw new PlatformApiException(
          409, "mail_worker_unavailable", "Mail worker operation unavailable.");
    }
  }

  /** Requires the optional private identity service. */
  private void requireVault() {
    if (vault == null)
      throw new PlatformApiException(503, "key_unavailable", "Mail vault unavailable.");
  }

  /**
   * Reads exactly one required request parameter.
   *
   * @param request authenticated fixed-route request
   * @param name required form parameter name
   * @return single request parameter value
   */
  private static String value(PlatformApiRequest request, String name) {
    var values = request.queryValues(name);
    if (values.size() != 1)
      throw new PlatformApiException(400, "mail_rejected", "Invalid Mail request.");
    return values.getFirst();
  }

  /**
   * Decodes bounded canonical private-operation input.
   *
   * @param request authenticated fixed-route request
   * @return decoded private operation bytes
   */
  private static byte[] payload(PlatformApiRequest request) {
    String value = value(request, "payloadBase64");
    if (value.length() > 262144) throw new IllegalArgumentException();
    byte[] bytes = Base64.getDecoder().decode(value);
    if (!Base64.getEncoder().encodeToString(bytes).equals(value))
      throw new IllegalArgumentException();
    return bytes;
  }

  /**
   * Creates a bounded authorization failure.
   *
   * @return bounded denial exception
   */
  private static PlatformApiException denied() {
    return new PlatformApiException(403, "forbidden", "Mail operation denied.");
  }
}
