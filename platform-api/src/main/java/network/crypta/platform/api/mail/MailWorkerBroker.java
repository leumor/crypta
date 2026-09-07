package network.crypta.platform.api.mail;

import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppTokenPrincipal;

/**
 * Transient, fixed Mail command broker; mailbox business state belongs to the child worker.
 *
 * <p>Callers must enforce own-browser identity for submit/result and process-only identity for
 * poll/reply before invoking this class. The launch identifier must come from authentication. No
 * method waits for a worker. Expired, stopped and replaced launch frames are discarded.
 */
public final class MailWorkerBroker {
  /** Maximum base64 text size including encoding overhead. */
  public static final int MAX_PAYLOAD_BASE64_BYTES = 384 * 1024;

  /** Maximum outstanding private requests before backpressure. */
  private static final int MAX_PENDING = 4;

  /** Maximum lifetime of a private request in milliseconds. */
  private static final long LIFETIME_MILLIS = 30_000;

  /** Closed own-app operation vocabulary accepted by the broker. */
  private static final Set<String> COMMANDS =
      Set.of(
          "initialize",
          "export-contact",
          "import-contact",
          "approve-contact",
          "revoke-contact",
          "save-draft",
          "preview-send",
          "confirm-send",
          "import-reference",
          "retry",
          "read",
          "status",
          "backup",
          "restore");

  /** Authoritative current verified AppHost launch. */
  private final AppHost host;

  /** Clock used for private-frame deadlines. */
  private final Clock clock;

  /** Bounded insertion-ordered requests guarded by the broker monitor. */
  private final LinkedHashMap<String, Pending> pending = new LinkedHashMap<>();

  /**
   * Creates a broker using the system clock.
   *
   * @param host authoritative process lifecycle
   */
  public MailWorkerBroker(AppHost host) {
    this(host, Clock.systemUTC());
  }

  /**
   * Creates a broker with an explicit clock for deadline verification.
   *
   * @param host authoritative process lifecycle
   * @param clock deadline clock
   */
  public MailWorkerBroker(AppHost host, Clock clock) {
    this.host = java.util.Objects.requireNonNull(host);
    this.clock = java.util.Objects.requireNonNull(clock);
  }

  /**
   * Queues one own-browser command for the currently running Mail process.
   *
   * @param command fixed allowed operation
   * @param payloadBase64 canonical base64 payload, never logged or parsed here
   * @return opaque request identifier
   */
  public synchronized String submit(String command, String payloadBase64) {
    if (!COMMANDS.contains(command)) throw failure("unsupported_command");
    validatePayload(payloadBase64);
    AppTokenPrincipal launch = current();
    expire(launch);
    if (pending.size() >= MAX_PENDING) throw failure("worker_busy");
    String id = UUID.randomUUID().toString();
    pending.put(
        id,
        new Pending(
            new Frame(id, launch.launchId(), launch.appVersion(), command, payloadBase64),
            clock.millis() + LIFETIME_MILLIS));
    return id;
  }

  /**
   * Returns the next undelivered frame for an authenticated live Mail process.
   *
   * @param launchId launch binding derived by process authentication
   * @return one frame or empty when no request is queued
   */
  public synchronized Optional<Frame> poll(String launchId) {
    AppTokenPrincipal launch = authorize(launchId);
    expire(launch);
    for (Pending request : pending.values()) {
      if (!request.polled) {
        request.polled = true;
        return Optional.of(request.frame);
      }
    }
    return Optional.empty();
  }

  /**
   * Completes exactly one polled request from the current authenticated launch.
   *
   * @param launchId authenticated process launch binding
   * @param requestId polled request identifier
   * @param payloadBase64 canonical bounded reply
   */
  public synchronized void reply(String launchId, String requestId, String payloadBase64) {
    validatePayload(payloadBase64);
    AppTokenPrincipal launch = authorize(launchId);
    expire(launch);
    Pending request = pending.get(requestId);
    if (request == null || !request.polled || request.reply != null) throw failure("stale_request");
    request.reply = payloadBase64;
  }

  /**
   * Consumes a completed own-browser result once.
   *
   * @param requestId identifier returned from submit
   * @return completed reply or empty while pending
   */
  public synchronized Optional<String> result(String requestId) {
    expire(current());
    Pending request = pending.get(requestId);
    if (request == null) throw failure("stale_request");
    if (request.reply == null) return Optional.empty();
    pending.remove(requestId);
    return Optional.of(request.reply);
  }

  /**
   * Requires a live launch and clears private frames when none exists.
   *
   * @return current live launch metadata
   */
  private AppTokenPrincipal current() {
    Optional<AppTokenPrincipal> launch = host.currentLaunch("mail-prototype");
    if (launch.isEmpty() || launch.get().launchId().isEmpty()) {
      pending.clear();
      throw failure("worker_unavailable");
    }
    return launch.get();
  }

  /**
   * Requires the exact authenticated current launch identifier.
   *
   * @param launchId authenticated current launch identifier
   * @return authorized current identity or launch metadata
   */
  private AppTokenPrincipal authorize(String launchId) {
    AppTokenPrincipal launch = current();
    if (!launch.launchId().equals(launchId)) throw failure("worker_unavailable");
    return launch;
  }

  /**
   * Discards timed-out frames and frames from another launch or version.
   *
   * @param launch current verified launch metadata
   */
  private void expire(AppTokenPrincipal launch) {
    long now = clock.millis();
    pending
        .values()
        .removeIf(
            request ->
                request.deadline <= now
                    || !request.frame.launchId().equals(launch.launchId())
                    || !request.frame.appVersion().equals(launch.appVersion()));
  }

  /**
   * Requires bounded canonical Base64 framing.
   *
   * @param value encoded or parsed input value
   */
  private static void validatePayload(String value) {
    if (value == null || value.length() > MAX_PAYLOAD_BASE64_BYTES) throw failure("invalid_frame");
    try {
      if (!Base64.getEncoder().encodeToString(Base64.getDecoder().decode(value)).equals(value))
        throw failure("invalid_frame");
    } catch (IllegalArgumentException exception) {
      throw failure("invalid_frame");
    }
  }

  /**
   * Creates a fixed broker failure without private request contents.
   *
   * @param code fixed bounded failure classification
   * @return bounded broker exception
   */
  private static IllegalStateException failure(String code) {
    return new IllegalStateException(code);
  }

  /**
   * A private transient process frame; its diagnostic representation omits all contents.
   *
   * @param requestId one-time request identifier
   * @param launchId exact launch generation
   * @param appVersion verified process bundle version
   * @param command fixed operation
   * @param payloadBase64 private canonical base64 payload
   */
  public record Frame(
      String requestId, String launchId, String appVersion, String command, String payloadBase64) {
    @Override
    public String toString() {
      return "MailWorkerFrame[redacted]";
    }
  }

  /** Transient one-launch request bookkeeping, never durable mailbox state. */
  private static final class Pending {
    /** Request bound to its verified launch and version. */
    final Frame frame;

    /** Absolute local-clock expiry time in milliseconds. */
    final long deadline;

    /** Whether the worker has already taken this request. */
    boolean polled;

    /** Canonical private reply, or null before completion. */
    String reply;

    /**
     * Initializes an undelivered request with an absolute expiry.
     *
     * @param frame private request bound to a launch
     * @param deadline absolute expiry time in local-clock milliseconds
     */
    Pending(Frame frame, long deadline) {
      this.frame = frame;
      this.deadline = deadline;
    }
  }
}
