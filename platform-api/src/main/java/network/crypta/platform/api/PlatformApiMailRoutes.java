package network.crypta.platform.api;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.mail.MailWorkerBroker;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppVaultService;

/**
 * Fixed own-app mediation and process-only vault routes for the experimental Mail application.
 *
 * <p>The central router must authenticate the principal, enforce experimental admission and check
 * the route capability before calling this handler. This layer additionally restricts callers to
 * {@code mail-prototype}, separates browser command/result access from process operations, and
 * checks current launch identity and permissions. Private responses are fenced again against a
 * replaced launch before release.
 *
 * <p>Only the enumerated actions and exact parameter sets are accepted; this is not an arbitrary
 * RPC, URL proxy or browser decryption interface. The broker holds transient request frames and the
 * vault performs purpose-scoped cryptography. Contacts, approval and mailbox persistence remain
 * owned by the child worker. Response bodies may contain private data and must not be logged.
 */
final class PlatformApiMailRoutes {
  /** Only app identity admitted to this fixed route family. */
  private static final String MAIL_APP_ID = "mail-prototype";

  /** Browser submission action and field naming the bounded worker operation. */
  private static final String COMMAND = "command";

  /** Browser action that consumes a completed worker result once. */
  private static final String RESULT_ACTION = "result";

  /** Parameter and response field carrying the canonical Base64 private payload. */
  private static final String PAYLOAD_BASE64 = "payloadBase64";

  /** Parameter and response field binding one transient worker request. */
  private static final String REQUEST_ID = "requestId";

  /** Process-only action protecting state under a retained storage identity. */
  private static final String SEAL_STORAGE = "seal-storage";

  /** Private-operation parameter and public metadata field naming a vault identity. */
  private static final String IDENTITY_ID = "identityId";

  /** Bounded response classification field. */
  private static final String STATUS = "status";

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
    if (!MAIL_APP_ID.equals(principal.appId())
        || request.pathSegments().size() != 2
        || !"POST".equals(request.method())
        || broker == null) throw denied();
    String action = request.pathSegments().get(1);
    boolean browser = principal.authSource() == PlatformApiAuthSource.APP_BROWSER_SESSION;
    if (browser != List.of(COMMAND, RESULT_ACTION).contains(action)) throw denied();
    if (!browser
        && (principal.launchId() == null
            || host.currentLaunch(MAIL_APP_ID)
                .filter(
                    p ->
                        p.launchId().equals(principal.launchId())
                            && p.permissions().equals(principal.permissions()))
                .isEmpty())) throw denied();
    java.util.Set<String> allowed =
        switch (action) {
          case COMMAND -> java.util.Set.of(COMMAND, PAYLOAD_BASE64);
          case RESULT_ACTION -> java.util.Set.of(REQUEST_ID);
          case "poll" -> java.util.Set.of();
          case "reply" -> java.util.Set.of(REQUEST_ID, PAYLOAD_BASE64);
          case "create-identity" -> java.util.Set.of("kind");
          case "sign", "open", SEAL_STORAGE, "open-storage" ->
              java.util.Set.of(IDENTITY_ID, PAYLOAD_BASE64);
          default -> throw denied();
        };
    if (!allowed.equals(request.queryParameters().keySet())) throw denied();
    try {
      Object response =
          switch (action) {
            case COMMAND ->
                Map.of(
                    REQUEST_ID,
                    broker.submit(value(request, COMMAND), value(request, PAYLOAD_BASE64)));
            case RESULT_ACTION -> {
              var result = broker.result(value(request, REQUEST_ID));
              yield result
                  .<Object>map(s -> Map.of(STATUS, "complete", PAYLOAD_BASE64, s))
                  .orElse(Map.of(STATUS, "pending"));
            }
            case "poll" -> {
              var frame = broker.poll(principal.launchId());
              yield frame
                  .<Object>map(
                      f ->
                          Map.of(
                              REQUEST_ID,
                              f.requestId(),
                              COMMAND,
                              f.command(),
                              PAYLOAD_BASE64,
                              f.payloadBase64()))
                  .orElse(Map.of(STATUS, "idle"));
            }
            case "reply" -> {
              broker.reply(
                  principal.launchId(), value(request, REQUEST_ID), value(request, PAYLOAD_BASE64));
              yield Map.of(STATUS, "ok");
            }
            case "create-identity" -> {
              requireVault();
              var identity =
                  vault.createMailIdentity(
                      principal.appId(), AppIdentityKind.fromJsonValue(value(request, "kind")));
              yield Map.of(
                  IDENTITY_ID,
                  identity.identityId(),
                  "fingerprint",
                  identity.fingerprint(),
                  "publicSummary",
                  identity.publicSummary());
            }
            case "sign", "open", SEAL_STORAGE, "open-storage" -> {
              requireVault();
              String identityId = value(request, IDENTITY_ID);
              byte[] payload = payload(request);
              byte[] result =
                  switch (action) {
                    case "sign" -> vault.signMail(principal.appId(), identityId, payload);
                    case "open" -> vault.openMail(principal.appId(), identityId, payload);
                    case SEAL_STORAGE -> vault.sealStorage(principal.appId(), identityId, payload);
                    default -> vault.openStorage(principal.appId(), identityId, payload);
                  };
              yield Map.of(PAYLOAD_BASE64, Base64.getEncoder().encodeToString(result));
            }
            default -> throw denied();
          };
      if (!browser
          && host.currentLaunch(MAIL_APP_ID)
              .filter(p -> p.launchId().equals(principal.launchId()))
              .isEmpty()) throw denied();
      return PlatformApiResponse.ok(Map.of("mail", response));
    } catch (IllegalArgumentException _) {
      throw new PlatformApiException(400, "mail_rejected", "Mail operation rejected.");
    } catch (IllegalStateException _) {
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
    String value = value(request, PAYLOAD_BASE64);
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
