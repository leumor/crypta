package network.crypta.apps.mail;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.crypt.mail.MailHpke;
import network.crypta.crypt.mail.MailWire;

/**
 * Single-writer mailbox state machine owned exclusively by the Mail child process. Each mutation
 * protects and CAS-publishes one complete dataset; network insertion follows seal commit.
 */
public final class MailMailbox {
  /** Maximum encoded plaintext dataset bytes, leaving private-channel backup headroom. */
  private static final int MAX_STATE = 112 * 1024;

  /** Seconds per policy day. */
  private static final long DAY = 86400;

  /** Authenticated local platform operations used by this child-owned state machine. */
  private final MailBackend backend;

  /** Clock used for explicit local validity and acceptance policy. */
  private final Clock clock;

  /** Secure source for independent keys and random identifiers. */
  private final SecureRandom random = new SecureRandom();

  /** Current private string-valued dataset, reloaded before each command. */
  private Map<String, String> state = new LinkedHashMap<>();

  /** CAS digest of the last loaded or committed protected dataset. */
  private String digest;

  /** Last loaded or committed protected dataset bytes used for deterministic backup. */
  private byte[] stored;

  /**
   * Constructs a worker-owned mailbox over an authenticated platform connection.
   *
   * @param backend authenticated endpoint operations; owns no mailbox business rules
   * @param clock clock used for local contact and message acceptance policy
   */
  public MailMailbox(MailBackend backend, Clock clock) {
    this.backend = backend;
    this.clock = clock;
  }

  /**
   * Executes one explicit own-UI operation; errors never include payloads or cryptographic details.
   *
   * <p>Calls are serialized. Each call reloads durable state; mutations are committed as a
   * protected dataset through app-data CAS before their dependent network insertion. Success
   * statuses describe local processing or insertion, never delivery or reading by another
   * installation.
   *
   * @param command fixed own-UI command selected by the private worker broker
   * @param input decoded string-valued command fields, potentially containing private plaintext
   * @return private result fields or a bounded failure status
   */
  public synchronized Map<String, String> execute(String command, Map<String, String> input) {
    try {
      try {
        load();
      } catch (IllegalArgumentException failure) {
        if (!"restore".equals(command)) throw failure;
        state = new LinkedHashMap<>();
      } catch (MailFailure failure) {
        if (!"restore".equals(command) || !"invalid".equals(failure.getMessage())) throw failure;
        state = new LinkedHashMap<>();
      }
      if ("initialize".equals(command)) return initialize();
      if ("restore".equals(command)) return restore(input);
      if (state.isEmpty()) throw new MailFailure("initialize-required");
      return switch (command) {
        case "status" -> status();
        case "export-contact" -> Map.of("card", state.get("ownCard"), "status", "public-export");
        case "import-contact" -> importContact(input);
        case "approve-contact" -> approveContact(input);
        case "revoke-contact" -> revokeContact(input);
        case "save-draft" -> saveDraft(input);
        case "preview-send" -> preview();
        case "confirm-send" -> send(input);
        case "retry" -> publish(required(input, "operation"));
        case "import-reference" -> receive(input);
        case "read" -> read(input);
        case "backup" ->
            Map.of("backup", MailWire.base64(stored), "status", "private-data-only-backup");
        default -> throw new MailFailure("invalid");
      };
    } catch (MailFailure e) {
      return Map.of("status", e.getMessage());
    } catch (IllegalArgumentException e) {
      return Map.of("status", "invalid");
    }
  }

  /** Reloads and authenticates durable state before checking retained key authority. */
  private void load() {
    state = new LinkedHashMap<>();
    digest = null;
    stored = null;
    Map<String, Object> record;
    try {
      record =
          object(
              backend
                  .request("GET", "/app-data/records/mail-state/dataset", Map.of())
                  .get("record"));
    } catch (MailFailure e) {
      if ("not-found".equals(e.getMessage())) return;
      throw e;
    }
    stored = decode(text(record, "valueBase64"), 262144);
    digest = text(record, "sha256");
    state = openState(stored);
    validateKeys();
  }

  /**
   * Authenticates a protected dataset and checks its storage identity and schema.
   *
   * @param data complete protected dataset bytes
   * @return authenticated private state fields
   */
  private Map<String, String> openState(byte[] data) {
    var outer = MailWire.ordered(MailWire.decode(data, 262144), List.of("storageId", "envelope"));
    byte[] plain =
        crypto("open-storage", outer.get("storageId"), decode(outer.get("envelope"), 196608));
    var result = new LinkedHashMap<>(MailWire.decode(plain, MAX_STATE));
    java.util.Arrays.fill(plain, (byte) 0);
    if (!"1".equals(result.get("schema"))
        || !outer.get("storageId").equals(result.get("storageId")))
      throw new MailFailure("recovery-required");
    return result;
  }

  /** Rechecks all retained identity metadata and current signing/recipient authority. */
  private void validateKeys() {
    try {
      for (String key : List.of("signingId", "recipientId", "storageId")) {
        String id = required(state, key);
        var record =
            object(backend.request("GET", "/app-vault/identities/" + id, Map.of()).get("identity"));
        if (record.isEmpty()) throw new MailFailure("key-unavailable");
      }
      // Contact signing rechecks both current signing and recipient-purpose grants and account
      // binding.
      crypto(
          "sign",
          state.get("signingId"),
          MailWire.signedPayload(state.get("ownCard").getBytes(StandardCharsets.UTF_8)));
    } catch (MailFailure failure) {
      throw new MailFailure("key-unavailable");
    }
  }

  /**
   * Creates the first retained account only when no prior identity requires recovery.
   *
   * @return private retained-account status
   */
  private Map<String, String> initialize() {
    if (!state.isEmpty()) return status();
    var identities = backend.request("GET", "/app-vault/identities", Map.of()).get("identities");
    if (identities instanceof List<?> list && !list.isEmpty())
      throw new MailFailure("recovery-required");
    var signing = mail("create-identity", Map.of("kind", "mail-signing-v1"));
    var recipient = mail("create-identity", Map.of("kind", "mail-recipient-v1"));
    var storage = mail("create-identity", Map.of("kind", "mail-storage-v1"));
    var signPublic = object(signing.get("publicSummary"));
    var recPublic = object(recipient.get("publicSummary"));
    state.put("schema", "1");
    state.put("signingId", text(signing, "identityId"));
    state.put("recipientId", text(recipient, "identityId"));
    state.put("storageId", text(storage, "identityId"));
    state.put("recovery", "normal");
    var card = new LinkedHashMap<String, String>();
    card.put("profile", MailWire.CONTACT);
    card.put("signingKey", text(signPublic, "publicKeyBase64"));
    card.put("signingFingerprint", text(signing, "fingerprint"));
    card.put("account", text(signPublic, "account"));
    card.put("signingEpoch", "1");
    card.put("recipientKey", text(recPublic, "publicKeyBase64"));
    card.put("recipientFingerprint", text(recipient, "fingerprint"));
    card.put("recipientEpoch", "1");
    card.put("created", Long.toString(now()));
    card.put("expires", Long.toString(now() + 365 * DAY));
    card.put("suite", "32/1/1");
    state.put(
        "ownCard",
        new String(
            crypto("sign", state.get("signingId"), MailWire.contactPayload(card)),
            StandardCharsets.UTF_8));
    commit();
    return status();
  }

  /**
   * Stages a validated contact for explicit fingerprint comparison.
   *
   * @param input private command fields
   * @return private comparison fields
   */
  private Map<String, String> importContact(Map<String, String> input) {
    String card = required(input, "card");
    var contact = contact(card, true);
    state.put("pendingContact", card);
    state.remove("approval");
    commit();
    return Map.of(
        "status",
        "compare-fingerprint-out-of-band",
        "fingerprint",
        contact.get("signingFingerprint"),
        "recipientFingerprint",
        contact.get("recipientFingerprint"),
        "account",
        contact.get("account"));
  }

  /**
   * Pins a manually compared contact without silently replacing an existing pin.
   *
   * @param input private command fields
   * @return private approval status
   */
  private Map<String, String> approveContact(Map<String, String> input) {
    String pending = required(state, "pendingContact");
    var card = contact(pending, true);
    String fp = required(input, "fingerprint");
    if (!fp.equals(card.get("signingFingerprint"))) throw new MailFailure("contact-mismatch");
    String prior = state.get("contact." + fp);
    if (prior != null && !prior.equals(pending)) throw new MailFailure("pin-change-blocked");
    for (var e : state.entrySet())
      if (e.getKey().startsWith("contact.")) {
        var c = contact(e.getValue(), false);
        if (c.get("account").equals(card.get("account")) && !e.getKey().equals("contact." + fp))
          throw new MailFailure("pin-change-blocked");
      }
    if (prior == null && count("contact.") >= 16) throw new MailFailure("quota");
    state.put("contact." + fp, pending);
    state.remove("pendingContact");
    state.remove("approval");
    commit();
    return Map.of("status", "contact-approved");
  }

  /**
   * Persists a contact revocation and invalidates pending send approval.
   *
   * @param input private command fields
   * @return private revocation result
   */
  private Map<String, String> revokeContact(Map<String, String> input) {
    String fp = required(input, "fingerprint");
    if (!state.containsKey("contact." + fp)) throw new MailFailure("unknown-sender-or-contact");
    state.put("revoked." + fp, "true");
    state.remove("approval");
    commit();
    return Map.of("status", "contact-revoked");
  }

  /**
   * Protects a bounded draft addressed to an active approved contact.
   *
   * @param input private command fields
   * @return private draft status
   */
  private Map<String, String> saveDraft(Map<String, String> input) {
    String fp = required(input, "fingerprint");
    approved(fp);
    String subject = required(input, "subject"), body = required(input, "body");
    if (subject.getBytes(StandardCharsets.UTF_8).length > 256
        || body.getBytes(StandardCharsets.UTF_8).length > 16384) throw new MailFailure("quota");
    state.put("draft", json(Map.of("fingerprint", fp, "subject", subject, "body", body)));
    state.remove("approval");
    commit();
    return Map.of("status", "draft");
  }

  /**
   * Commits approval binding to the exact draft and approved contact.
   *
   * @return exact private preview and approval binding
   */
  private Map<String, String> preview() {
    var draft = fields(required(state, "draft"), 32768);
    var recipient = approved(draft.get("fingerprint"));
    String approval =
        hash(
            (state.get("draft") + state.get("contact." + draft.get("fingerprint")))
                .getBytes(StandardCharsets.UTF_8));
    state.put("approval", approval);
    commit();
    return Map.of(
        "status",
        "approval-required",
        "approval",
        approval,
        "recipientFingerprint",
        recipient.get("recipientFingerprint"),
        "recipientEpoch",
        recipient.get("recipientEpoch"),
        "subject",
        draft.get("subject"),
        "body",
        draft.get("body"));
  }

  /**
   * Seals an explicitly approved message and commits it before insertion.
   *
   * @param input private command fields
   * @return queued or inserted result after seal commit
   */
  private Map<String, String> send(Map<String, String> input) {
    if (!"normal".equals(state.get("recovery"))) throw new MailFailure("recovery-paused");
    if (count("outbox.") >= 8) throw new MailFailure("quota");
    String approval = required(input, "approval");
    if (!approval.equals(state.get("approval"))) throw new MailFailure("approval-required");
    var draft = fields(required(state, "draft"), 32768);
    var recipient = approved(draft.get("fingerprint"));
    var own = contact(state.get("ownCard"), true);
    if (!approval.equals(
        hash(
            (state.get("draft") + state.get("contact." + draft.get("fingerprint")))
                .getBytes(StandardCharsets.UTF_8)))) throw new MailFailure("approval-required");
    var msg = new LinkedHashMap<String, String>();
    msg.put("profile", MailWire.MESSAGE);
    String id = randomId();
    msg.put("messageId", id);
    msg.put("sender", own.get("signingFingerprint"));
    msg.put("senderAccount", own.get("account"));
    msg.put("senderEpoch", own.get("signingEpoch"));
    msg.put("recipient", recipient.get("recipientFingerprint"));
    msg.put("recipientAccount", recipient.get("account"));
    msg.put("recipientEpoch", recipient.get("recipientEpoch"));
    msg.put("created", Long.toString(now()));
    msg.put(
        "expires",
        Long.toString(
            Math.min(
                now() + 30 * DAY,
                Math.min(
                    MailWire.decimal(recipient.get("expires")),
                    MailWire.decimal(own.get("expires"))))));
    msg.put("subject", draft.get("subject"));
    msg.put("body", draft.get("body"));
    msg.put("format", "text/plain");
    byte[] signed = crypto("sign", state.get("signingId"), MailWire.messagePayload(msg));
    byte[] sealed =
        MailHpke.seal(
            "network",
            recipient.get("recipientFingerprint"),
            MailWire.unbase64(recipient.get("recipientKey"), 32),
            signed);
    var out = new LinkedHashMap<String, String>();
    out.put("state", "sealed");
    out.put("contact", draft.get("fingerprint"));
    out.put("envelope", MailWire.base64(sealed));
    out.put("signed", MailWire.base64(signed));
    out.put("reference", "");
    state.put("outbox." + id, json(out));
    state.remove("approval");
    state.remove("draft");
    commit();
    return publish(id);
  }

  /**
   * Recovers insertion state and publishes only committed immutable ciphertext.
   *
   * @param operation stable committed outbox operation identifier
   * @return private queued or inserted result
   */
  private Map<String, String> publish(String operation) {
    if (!operation.matches("[0-9a-f]{32}")) throw new MailFailure("invalid");
    var out = fields(required(state, "outbox." + operation), MAX_STATE);
    if ("inserted".equals(out.get("state")))
      return Map.of(
          "status", "inserted", "operation", operation, "reference", out.get("reference"));
    String identifier = "app-document-mail-prototype-" + operation;
    var progress =
        backend.request("GET", "/queue/app-document-status", Map.of("identifier", identifier));
    String status = text(progress, "state");
    if ("inserted".equals(status)) {
      String reference = text(progress, "reference");
      requireChk(reference);
      out.put("state", "inserted");
      out.put("reference", reference);
      state.put("outbox." + operation, json(out));
      commit();
      return Map.of("status", "inserted", "operation", operation, "reference", reference);
    }
    if ("failed".equals(status) || "missing".equals(status)) {
      if (!"normal".equals(state.get("recovery"))) throw new MailFailure("recovery-paused");
      requireUnexpiredOutboxMessage(out);
      approved(required(out, "contact"));
    }
    if ("failed".equals(status)) {
      backend.request("POST", "/queue/restart", Map.of("identifier", identifier));
    } else if ("missing".equals(status)) {
      // These committed immutable bytes are the only application bytes ever inserted.
      backend.request(
          "POST",
          "/queue/inserts/app-document",
          Map.of(
              "insertUri",
              "CHK@",
              "identifier",
              identifier,
              "documentBase64",
              out.get("envelope"),
              "contentType",
              "application/vnd.crypta.mail+json",
              "targetFilename",
              "mail.json"));
    }
    out.put("state", "queued");
    state.put("outbox." + operation, json(out));
    commit();
    return Map.of(
        "status",
        "queued",
        "operation",
        operation,
        "note",
        "Retry checks insertion; insertion is not delivery or reading.");
  }

  /**
   * Checks the retained signed expiry before initiating or restarting network publication.
   *
   * @param outbox immutable sealed outbox entry protected by the local storage envelope
   */
  private void requireUnexpiredOutboxMessage(Map<String, String> outbox) {
    byte[] signed = decode(required(outbox, "signed"), 45056);
    var message = MailWire.decode(MailWire.signedPayload(signed), 32768);
    MailWire.messagePayload(message);
    if (MailWire.decimal(message.get("expires")) <= now()) throw new MailFailure("expired");
  }

  /**
   * Fetches by explicit consent and atomically admits verified mail with replay evidence.
   *
   * @param input private command fields
   * @return bounded acceptance, duplicate or rejection status
   */
  private Map<String, String> receive(Map<String, String> input) {
    if (!"yes".equals(input.get("confirmed"))) throw new MailFailure("network-consent-required");
    if (!"normal".equals(state.get("recovery"))) throw new MailFailure("recovery-paused");
    if (count("replay.") >= 128 || count("inbox.") >= 16) throw new MailFailure("quota");
    String reference = required(input, "reference");
    requireChk(reference);
    var response =
        backend.request(
            "POST",
            "/content/fetch",
            Map.of(
                "uri",
                reference,
                "maxBytes",
                "65536",
                "timeoutMillis",
                "20000",
                "format",
                "base64",
                "purpose",
                "mail-explicit-import"));
    byte[] envelope = decode(text(response, "contentBase64"), 65536);
    MailHpke.validateNetworkEnvelope(envelope);
    var visibleHeader = MailWire.decode(envelope, 65536);
    var localCard = contact(state.get("ownCard"), false);
    if (!localCard.get("recipientFingerprint").equals(visibleHeader.get("selector")))
      throw new MailFailure("wrong-recipient");
    byte[] signed = crypto("open", state.get("recipientId"), envelope);
    byte[] payload = MailWire.signedPayload(signed);
    var msg = MailWire.decode(payload, 32768);
    MailWire.messagePayload(msg);
    if (!state.containsKey("contact." + required(msg, "sender")))
      throw new MailFailure("unknown-sender");
    var sender = approved(required(msg, "sender"));
    if (!MailWire.verify(
        MailWire.unbase64(sender.get("signingKey"), 32),
        MailWire.preimage(MailWire.MESSAGE, payload),
        MailWire.signature(signed))) throw new MailFailure("invalid");
    var own = contact(state.get("ownCard"), false);
    for (String[] pair :
        List.of(
            new String[] {"senderAccount", "account"},
            new String[] {"senderEpoch", "signingEpoch"}))
      if (!msg.get(pair[0]).equals(sender.get(pair[1]))) throw new MailFailure("contact-mismatch");
    if (!msg.get("recipient").equals(own.get("recipientFingerprint"))
        || !msg.get("recipientAccount").equals(own.get("account"))
        || !msg.get("recipientEpoch").equals(own.get("recipientEpoch")))
      throw new MailFailure("wrong-recipient");
    long created = MailWire.decimal(msg.get("created")),
        expires = MailWire.decimal(msg.get("expires"));
    if (created > now() + 300
        || expires <= now()
        || expires - created > 30 * DAY
        || created < MailWire.decimal(sender.get("created"))
        || expires > MailWire.decimal(sender.get("expires"))
        || created < MailWire.decimal(own.get("created"))
        || expires > MailWire.decimal(own.get("expires"))) throw new MailFailure("expired");
    String replay =
        hash(
            (own.get("account")
                    + ":"
                    + own.get("recipientFingerprint")
                    + ":"
                    + own.get("recipientEpoch")
                    + ":"
                    + msg.get("sender")
                    + ":"
                    + msg.get("senderEpoch")
                    + ":"
                    + msg.get("messageId"))
                .getBytes(StandardCharsets.UTF_8));
    String digest = hash(payload), previous = state.get("replay." + replay);
    if (previous != null)
      return Map.of("status", previous.equals(digest) ? "duplicate" : "conflict");
    state.put("replay." + replay, digest);
    state.put("inbox." + replay, MailWire.base64(signed));
    commit();
    return Map.of("status", "accepted", "messageId", replay, "senderTrust", "locally-pinned");
  }

  /**
   * Returns literal content from an already accepted protected local copy.
   *
   * @param input private command fields
   * @return literal verified-local-copy fields
   */
  private Map<String, String> read(Map<String, String> input) {
    String id = required(input, "messageId");
    var message =
        MailWire.decode(
            MailWire.signedPayload(decode(required(state, "inbox." + id), 45056)), 32768);
    return Map.of(
        "status",
        "verified-local-copy",
        "sender",
        message.get("sender"),
        "subject",
        message.get("subject"),
        "body",
        message.get("body"),
        "format",
        "text/plain",
        "senderTrust",
        "locally-pinned-at-acceptance");
  }

  /**
   * Restores retained-key state while preserving available revocation and replay evidence.
   *
   * @param input private command fields
   * @return explicit recovery-paused status
   */
  private Map<String, String> restore(Map<String, String> input) {
    if (!"yes".equals(input.get("confirmed")))
      throw new MailFailure("recovery-confirmation-required");
    var current = state;
    var restored = openState(decode(required(input, "backup"), 262144));
    if (!current.isEmpty() && !current.get("storageId").equals(restored.get("storageId")))
      throw new MailFailure("key-unavailable");
    for (var entry : current.entrySet())
      if (entry.getKey().startsWith("replay.") || entry.getKey().startsWith("revoked.")) {
        String old = restored.putIfAbsent(entry.getKey(), entry.getValue());
        if (old != null && !old.equals(entry.getValue())) throw new MailFailure("conflict");
      }
    state = restored;
    state.put("recovery", "paused-after-restore");
    state.remove("approval");
    validateKeys();
    commit();
    return Map.of(
        "status",
        "recovery-paused",
        "note",
        "Available replay evidence merged. Receiving is paused after restore; full rollback is not"
            + " detectable. Read/export remain available.");
  }

  /**
   * Returns private counts and identifiers without performing network delivery discovery.
   *
   * @return private mailbox summary
   */
  private Map<String, String> status() {
    var result = new LinkedHashMap<String, String>();
    result.put("status", "ready");
    result.put("recovery", state.get("recovery"));
    result.put("contacts", Long.toString(count("contact.")));
    result.put(
        "contactFingerprints",
        String.join(
            ",",
            state.keySet().stream()
                .filter(k -> k.startsWith("contact."))
                .map(k -> k.substring(8))
                .toList()));
    result.put("inbox", Long.toString(count("inbox.")));
    result.put("outbox", Long.toString(count("outbox.")));
    result.put(
        "messageIds",
        String.join(
            ",",
            state.keySet().stream()
                .filter(k -> k.startsWith("inbox."))
                .map(k -> k.substring(6))
                .toList()));
    result.put(
        "operations",
        String.join(
            ",",
            state.keySet().stream()
                .filter(k -> k.startsWith("outbox."))
                .map(k -> k.substring(7))
                .toList()));
    return result;
  }

  /**
   * Returns an active pinned contact only when no local revocation exists.
   *
   * @param fp locally pinned signing fingerprint
   * @return validated active contact fields
   */
  private Map<String, String> approved(String fp) {
    if (state.containsKey("revoked." + fp)) throw new MailFailure("contact-revoked");
    String card = state.get("contact." + fp);
    if (card == null) throw new MailFailure("unknown-sender-or-contact");
    return contact(card, true);
  }

  /**
   * Validates the exact signed pairing and optional current-validity policy.
   *
   * @param card complete signed public contact wrapper
   * @param active whether current contact validity is required
   * @return validated pairing fields
   */
  private Map<String, String> contact(String card, boolean active) {
    byte[] wrapper = card.getBytes(StandardCharsets.UTF_8),
        payload = MailWire.signedPayload(wrapper);
    var contact = MailWire.decode(payload, 4096);
    MailWire.contactPayload(contact);
    if (!MailWire.verify(
        MailWire.unbase64(contact.get("signingKey"), 32),
        MailWire.preimage(MailWire.CONTACT, payload),
        MailWire.signature(wrapper))) throw new MailFailure("invalid-contact");
    if (active
        && (MailWire.decimal(contact.get("created")) > now() + 300
            || MailWire.decimal(contact.get("expires")) <= now()))
      throw new MailFailure("expired-contact");
    return contact;
  }

  /** Protects and CAS-publishes the complete dataset with insertion-completion headroom. */
  private void commit() {
    byte[] plaintext = MailWire.encode(state);
    if (plaintext.length + completionReserve() > MAX_STATE || count("replay.") > 128)
      throw new MailFailure("quota");
    byte[] envelope = crypto("seal-storage", state.get("storageId"), plaintext);
    java.util.Arrays.fill(plaintext, (byte) 0);
    var wrapper = new LinkedHashMap<String, String>();
    wrapper.put("storageId", state.get("storageId"));
    wrapper.put("envelope", MailWire.base64(envelope));
    byte[] value = MailWire.encode(wrapper);
    if (value.length > 262144) throw new MailFailure("quota");
    var parameters = new LinkedHashMap<String, String>();
    parameters.put("namespace", "mail-state");
    parameters.put("key", "dataset");
    parameters.put("schemaVersion", "1");
    parameters.put("contentType", "application/octet-stream");
    parameters.put("valueBase64", MailWire.base64(value));
    if (digest != null) parameters.put("ifMatchSha256", digest);
    var record = object(backend.request("POST", "/app-data/records", parameters).get("record"));
    digest = text(record, "sha256");
    stored = value;
  }

  /**
   * Reserves bytes for references on pending outbox records.
   *
   * @return required future completion bytes
   */
  private int completionReserve() {
    int bytes = 0;
    for (var entry : state.entrySet()) {
      if (entry.getKey().startsWith("outbox.")
          && !"inserted".equals(fields(entry.getValue(), MAX_STATE).get("state"))) bytes += 256;
    }
    return bytes;
  }

  /**
   * Invokes one purpose-scoped vault operation and decodes its bounded response.
   *
   * @param action fixed Mail endpoint operation
   * @param id retained identity or record identifier
   * @param payload complete bounded operation bytes
   * @return bounded vault response bytes
   */
  private byte[] crypto(String action, String id, byte[] payload) {
    return decode(
        text(
            mail(action, Map.of("identityId", id, "payloadBase64", MailWire.base64(payload))),
            "payloadBase64"),
        196608);
  }

  /**
   * Calls one fixed process-only Mail route and extracts its response object.
   *
   * @param action fixed Mail endpoint operation
   * @param parameters private fixed-route form parameters
   * @return parsed private Mail response object
   */
  private Map<String, Object> mail(String action, Map<String, String> parameters) {
    return object(backend.request("POST", "/mail/" + action, parameters).get("mail"));
  }

  /**
   * Counts dataset entries belonging to a bounded record family.
   *
   * @param prefix private record-family prefix
   * @return number of matching private entries
   */
  private long count(String prefix) {
    return state.keySet().stream().filter(k -> k.startsWith(prefix)).count();
  }

  /**
   * Returns the local acceptance time in epoch seconds.
   *
   * @return epoch seconds
   */
  private long now() {
    return clock.instant().getEpochSecond();
  }

  /**
   * Generates a fresh unrelated 128-bit message or operation identifier.
   *
   * @return 32 lowercase hexadecimal characters
   */
  private String randomId() {
    byte[] bytes = new byte[16];
    random.nextBytes(bytes);
    return HexFormat.of().formatHex(bytes);
  }

  /**
   * Computes a local SHA-256 state or replay digest, never a random message identifier.
   *
   * @param bytes complete bytes to hash
   * @return lowercase SHA-256 digest
   */
  private static String hash(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Restricts handoff input to the bounded CHK reference grammar.
   *
   * @param reference manually handed-off CHK reference
   */
  private static void requireChk(String reference) {
    if (!reference.matches(
        "CHK@[A-Za-z0-9~-]{43},[A-Za-z0-9~-]{43},[A-Za-z0-9~-]{7}(/[A-Za-z0-9._-]{1,64})?"))
      throw new MailFailure("invalid-reference");
  }

  /**
   * Decodes bounded canonical Base64.
   *
   * @param value encoded or parsed input value
   * @param max maximum decoded or encoded byte count
   * @return decoded bytes
   */
  private static byte[] decode(String value, int max) {
    if (value.length() > 4 * ((max + 2) / 3)) throw new MailFailure("quota");
    byte[] bytes = Base64.getDecoder().decode(value);
    if (bytes.length > max || !MailWire.base64(bytes).equals(value))
      throw new MailFailure("invalid");
    return bytes;
  }

  /**
   * Decodes a bounded canonical flat JSON object.
   *
   * @param value encoded or parsed input value
   * @param max maximum decoded or encoded byte count
   * @return parsed private string fields
   */
  private static Map<String, String> fields(String value, int max) {
    return new LinkedHashMap<>(MailWire.decode(value.getBytes(StandardCharsets.UTF_8), max));
  }

  /**
   * Encodes private string-valued fields as canonical JSON.
   *
   * @param values ordered string-valued fields
   * @return canonical JSON string
   */
  private static String json(Map<String, String> values) {
    return new String(MailWire.encode(values), StandardCharsets.UTF_8);
  }

  /**
   * Reads a required string field without supplying an implicit default.
   *
   * @param fields private parsed string fields
   * @param key required field name
   * @return required string value
   */
  private static String required(Map<String, String> fields, String key) {
    String value = fields.get(key);
    if (value == null) throw new MailFailure("invalid");
    return value;
  }

  /**
   * Reads one required string from a parsed local response.
   *
   * @param map parsed local response object
   * @param key required field name
   * @return required string response value
   */
  private static String text(Map<String, Object> map, String key) {
    if (!(map.get(key) instanceof String value)) throw new MailFailure("invalid");
    return value;
  }

  /**
   * Requires an object-shaped local API response.
   *
   * @param value encoded or parsed input value
   * @return parsed object fields
   */
  private static Map<String, Object> object(Object value) {
    return MailPlatformClient.object(value);
  }
}
