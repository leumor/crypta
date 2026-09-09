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
 *
 * <p>Use one instance in the AppHost-managed Mail worker. Private keys remain behind typed vault
 * operations; contact pins, drafts, sent copies, accepted messages and replay evidence belong to
 * this process and are persisted together under a separate storage key. Returned maps may contain
 * intentional plaintext for the own-app UI and must not enter public logs.
 *
 * <p>The prototype accepts one recipient and plain UTF-8 text through explicit CHK handoff. The
 * protected dataset has a 112 KiB plaintext cap, 16 contacts, 16 inbox records, eight outbox
 * operations and 128 replay entries; encoded byte limits may be reached before record limits.
 * Data-only restore requires retained vault identities, merges available replay/revocation
 * evidence, and pauses new sending and receiving. This class supplies no rollback-proof replay
 * guarantee.
 */
public final class MailMailbox {
  /** Command that imports protected state and pauses new sending and receiving. */
  private static final String RESTORE = "restore";

  /** Result field and command for the private local mailbox status. */
  private static final String STATUS = "status";

  /** Dataset field containing the signed public card for this retained account. */
  private static final String OWN_CARD = "ownCard";

  /** Command/result field identifying an immutable outbox operation. */
  private static final String OPERATION = "operation";

  /** Export command and field containing Base64-protected state without vault keys. */
  private static final String BACKUP = "backup";

  /** Dataset and wrapper field binding state to its retained storage identity. */
  private static final String STORAGE_ID = "storageId";

  /** Field containing a complete Base64-encoded encrypted envelope. */
  private static final String ENVELOPE = "envelope";

  /** Dataset field identifying the retained Mail signing identity. */
  private static final String SIGNING_ID = "signingId";

  /** Dataset field identifying the retained Mail decryption identity. */
  private static final String RECIPIENT_ID = "recipientId";

  /** Vault request/response field naming a retained identity. */
  private static final String IDENTITY_ID = "identityId";

  /** Dataset and status field describing whether sending and receiving are paused. */
  private static final String RECOVERY = "recovery";

  /** Recovery state that permits explicitly approved sending and receiving. */
  private static final String NORMAL = "normal";

  /** Dataset field marking resumed setup without claiming rollback-proof history. */
  private static final String INITIALIZATION_RECOVERY_EPOCH = "initializationRecoveryEpoch";

  /** Contact field containing the Base64-encoded Ed25519 public key. */
  private static final String SIGNING_KEY = "signingKey";

  /** Contact field containing the role-qualified signing-key fingerprint. */
  private static final String SIGNING_FINGERPRINT = "signingFingerprint";

  /** Public metadata and command field selecting a locally pinned signing identity. */
  private static final String FINGERPRINT = "fingerprint";

  /** Contact and public metadata field binding keys to one Mail account. */
  private static final String ACCOUNT = "account";

  /** Contact field containing the canonical signing-key epoch. */
  private static final String SIGNING_EPOCH = "signingEpoch";

  /** Contact and preview field identifying the intended encryption key. */
  private static final String RECIPIENT_FINGERPRINT = "recipientFingerprint";

  /** Contact, message and preview field containing the recipient-key epoch. */
  private static final String RECIPIENT_EPOCH = "recipientEpoch";

  /** Signed payload field containing creation time in epoch seconds. */
  private static final String CREATED = "created";

  /** Signed payload field containing exclusive expiry time in epoch seconds. */
  private static final String EXPIRES = "expires";

  /** Dataset field retaining a card awaiting explicit fingerprint approval. */
  private static final String PENDING_CONTACT = "pendingContact";

  /** Dataset and command field binding send approval to exact draft and contact bytes. */
  private static final String APPROVAL = "approval";

  /** Record prefix for locally pinned contact cards in the protected dataset. */
  private static final String CONTACT_PREFIX = "contact.";

  /** Record prefix for contact revocations retained through data restore. */
  private static final String REVOKED_PREFIX = "revoked.";

  /** Draft and signed-message field containing literal plain-text subject text. */
  private static final String SUBJECT = "subject";

  /** Dataset field and status value for the single saved draft. */
  private static final String DRAFT = "draft";

  /** Record prefix for committed outbound envelopes and insertion state. */
  private static final String OUTBOX_PREFIX = "outbox.";

  /** Outbox field describing the local publication state. */
  private static final String FIELD_STATE = "state";

  /** Command and result field containing a manually handed-off CHK read reference. */
  private static final String REFERENCE = "reference";

  /** Signed random message identifier or, in local results, the inbox replay key. */
  private static final String MESSAGE_ID = "messageId";

  /** Signed-message field identifying the sender signing-key fingerprint. */
  private static final String SENDER = "sender";

  /** Signed-message field containing the sender signing-key epoch. */
  private static final String SENDER_EPOCH = "senderEpoch";

  /** Signed-message and read-result field fixing content to plain text. */
  private static final String FORMAT = "format";

  /** Publication state indicating insertion, without delivery or read confirmation. */
  private static final String INSERTED = "inserted";

  /** Queue field naming the stable app-scoped insertion operation. */
  private static final String IDENTIFIER = "identifier";

  /** Record prefix for authenticated payload digests used for replay/conflict detection. */
  private static final String REPLAY_PREFIX = "replay.";

  /** Record prefix for accepted signed messages inside the protected dataset. */
  private static final String INBOX_PREFIX = "inbox.";

  /** Maximum encoded plaintext dataset bytes, leaving private-channel backup headroom. */
  private static final int MAX_STATE = 112 * 1024;

  /** Encoded unsigned message budget, reserving room for signed and sealed outbox copies. */
  private static final int MAX_COMPOSED_MESSAGE = 20 * 1024;

  /** Non-sensitive setup intent, atomically replaced by the first encrypted dataset. */
  private static final byte[] INITIALIZING =
      MailWire.encode(Map.of("initialization", "crypta.mail.initialization.v1"));

  /** Seconds per policy day. */
  private static final long DAY = 86400;

  /** Authenticated local platform operations used by this child-owned state machine. */
  private final MailBackend backend;

  /** Clock used for explicit local validity and acceptance policy. */
  private final Clock clock;

  /** Secure source for random message, operation and recovery identifiers. */
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
      loadForCommand(command);
      if ("initialize".equals(command)) return initialize();
      if (RESTORE.equals(command)) return restore(input);
      if (state.isEmpty()) throw new MailFailure("initialize-required");
      return switch (command) {
        case STATUS -> status();
        case "export-contact" -> Map.of("card", state.get(OWN_CARD), STATUS, "public-export");
        case "import-contact" -> importContact(input);
        case "approve-contact" -> approveContact(input);
        case "revoke-contact" -> revokeContact(input);
        case "save-draft" -> saveDraft(input);
        case "preview-send" -> preview();
        case "confirm-send" -> send(input);
        case "retry" -> publish(required(input, OPERATION));
        case "import-reference" -> receive(input);
        case "read" -> read(input);
        case BACKUP -> Map.of(BACKUP, MailWire.base64(stored), STATUS, "private-data-only-backup");
        default -> throw new MailFailure("invalid");
      };
    } catch (MailFailure e) {
      return Map.of(STATUS, e.getMessage());
    } catch (IllegalArgumentException _) {
      return Map.of(STATUS, "invalid");
    }
  }

  /**
   * Reloads state while permitting explicit restore to replace malformed stored data.
   *
   * @param command fixed own-app operation; only restore may replace malformed state
   */
  private void loadForCommand(String command) {
    try {
      load();
    } catch (IllegalArgumentException failure) {
      if (!RESTORE.equals(command)) throw failure;
      state = new LinkedHashMap<>();
    } catch (MailFailure failure) {
      if (!RESTORE.equals(command) || !"invalid".equals(failure.getMessage())) throw failure;
      state = new LinkedHashMap<>();
    }
  }

  /** Reloads and authenticates durable state before checking retained key authority. */
  private void load() {
    state = new LinkedHashMap<>();
    digest = null;
    stored = null;
    Map<String, Object> metadataRecord;
    try {
      metadataRecord =
          object(
              backend
                  .request("GET", "/app-data/records/mail-state/dataset", Map.of())
                  .get("record"));
    } catch (MailFailure e) {
      if ("not-found".equals(e.getMessage())) return;
      throw e;
    }
    stored = decode(text(metadataRecord, "valueBase64"), 262144);
    digest = text(metadataRecord, "sha256");
    if (java.util.Arrays.equals(stored, INITIALIZING)) return;
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
    var outer = MailWire.ordered(MailWire.decode(data, 262144), List.of(STORAGE_ID, ENVELOPE));
    byte[] plain =
        crypto("open-storage", outer.get(STORAGE_ID), decode(outer.get(ENVELOPE), 196608));
    var result = new LinkedHashMap<>(MailWire.decode(plain, MAX_STATE));
    java.util.Arrays.fill(plain, (byte) 0);
    if (!"1".equals(result.get("schema")) || !outer.get(STORAGE_ID).equals(result.get(STORAGE_ID)))
      throw new MailFailure("recovery-required");
    return result;
  }

  /** Rechecks all retained identity metadata and current signing/recipient authority. */
  private void validateKeys() {
    try {
      for (String key : List.of(SIGNING_ID, RECIPIENT_ID, STORAGE_ID)) {
        String id = required(state, key);
        var metadataRecord =
            object(backend.request("GET", "/app-vault/identities/" + id, Map.of()).get("identity"));
        if (metadataRecord.isEmpty()) throw new MailFailure("key-unavailable");
      }
      // Contact signing rechecks both current signing and recipient-purpose grants and account
      // binding.
      crypto(
          "sign",
          state.get(SIGNING_ID),
          MailWire.signedPayload(state.get(OWN_CARD).getBytes(StandardCharsets.UTF_8)));
    } catch (MailFailure _) {
      throw new MailFailure("key-unavailable");
    }
  }

  /**
   * Resumes marked first-time setup without replacing an established account.
   *
   * <p>The marker is durable before any key creation. Only a marker permits reconciliation of
   * partially created identities; the completed encrypted dataset replaces it through CAS. Missing
   * data with retained identities and no marker remains a recovery error.
   *
   * @return private retained-account status
   */
  private Map<String, String> initialize() {
    if (!state.isEmpty()) return status();
    var visible = backend.request("GET", "/app-vault/identities", Map.of()).get("identities");
    if (!(visible instanceof List<?> identities)) throw new MailFailure("recovery-required");
    boolean resumed = stored != null;
    if (stored == null) {
      if (!identities.isEmpty()) throw new MailFailure("recovery-required");
      storeDataset(INITIALIZING);
    }
    var retained = new LinkedHashMap<String, Map<String, Object>>();
    for (Object value : identities) {
      var identity = object(value);
      String kind = text(identity, "kind");
      if (!List.of("mail-signing-v1", "mail-recipient-v1", "mail-storage-v1").contains(kind)
          || retained.putIfAbsent(kind, identity) != null)
        throw new MailFailure("recovery-required");
    }
    var signing = initializationIdentity(retained, "mail-signing-v1");
    var recipient = initializationIdentity(retained, "mail-recipient-v1");
    var storage = initializationIdentity(retained, "mail-storage-v1");
    var signPublic = object(signing.get("publicSummary"));
    var recPublic = object(recipient.get("publicSummary"));
    state.put("schema", "1");
    state.put(SIGNING_ID, text(signing, IDENTITY_ID));
    state.put(RECIPIENT_ID, text(recipient, IDENTITY_ID));
    state.put(STORAGE_ID, text(storage, IDENTITY_ID));
    state.put(RECOVERY, NORMAL);
    if (resumed) state.put(INITIALIZATION_RECOVERY_EPOCH, randomId());
    var card = new LinkedHashMap<String, String>();
    card.put("profile", MailWire.CONTACT);
    card.put(SIGNING_KEY, text(signPublic, "publicKeyBase64"));
    card.put(SIGNING_FINGERPRINT, text(signing, FINGERPRINT));
    card.put(ACCOUNT, text(signPublic, ACCOUNT));
    card.put(SIGNING_EPOCH, "1");
    card.put("recipientKey", text(recPublic, "publicKeyBase64"));
    card.put(RECIPIENT_FINGERPRINT, text(recipient, FINGERPRINT));
    card.put(RECIPIENT_EPOCH, "1");
    card.put(CREATED, Long.toString(now()));
    card.put(EXPIRES, Long.toString(now() + 365 * DAY));
    card.put("suite", "32/1/1");
    state.put(
        OWN_CARD,
        new String(
            crypto("sign", state.get(SIGNING_ID), MailWire.contactPayload(card)),
            StandardCharsets.UTF_8));
    commit();
    return status();
  }

  /**
   * Reuses the sole retained purpose identity after a lost creation response.
   *
   * @param retained metadata from the current authorized identity list
   * @param kind dedicated purpose required by setup
   * @return existing or newly created public identity metadata
   */
  private Map<String, Object> initializationIdentity(
      Map<String, Map<String, Object>> retained, String kind) {
    var identity = retained.get(kind);
    return identity != null ? identity : mail("create-identity", Map.of("kind", kind));
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
    state.put(PENDING_CONTACT, card);
    state.remove(APPROVAL);
    commit();
    return Map.of(
        STATUS,
        "compare-fingerprint-out-of-band",
        FINGERPRINT,
        contact.get(SIGNING_FINGERPRINT),
        RECIPIENT_FINGERPRINT,
        contact.get(RECIPIENT_FINGERPRINT),
        ACCOUNT,
        contact.get(ACCOUNT));
  }

  /**
   * Pins a manually compared contact without silently replacing an existing pin.
   *
   * @param input private command fields
   * @return private approval status
   */
  private Map<String, String> approveContact(Map<String, String> input) {
    String pending = required(state, PENDING_CONTACT);
    var card = contact(pending, true);
    String fp = required(input, FINGERPRINT);
    if (!fp.equals(card.get(SIGNING_FINGERPRINT))) throw new MailFailure("contact-mismatch");
    String prior = state.get(CONTACT_PREFIX + fp);
    if (prior != null && !prior.equals(pending)) throw new MailFailure("pin-change-blocked");
    for (var e : state.entrySet())
      if (e.getKey().startsWith(CONTACT_PREFIX)) {
        var c = contact(e.getValue(), false);
        if (c.get(ACCOUNT).equals(card.get(ACCOUNT)) && !e.getKey().equals(CONTACT_PREFIX + fp))
          throw new MailFailure("pin-change-blocked");
      }
    if (prior == null && count(CONTACT_PREFIX) >= 16) throw new MailFailure("quota");
    state.put(CONTACT_PREFIX + fp, pending);
    state.remove(PENDING_CONTACT);
    state.remove(APPROVAL);
    commit();
    return Map.of(STATUS, "contact-approved");
  }

  /**
   * Persists a contact revocation and invalidates pending send approval.
   *
   * @param input private command fields
   * @return private revocation result
   */
  private Map<String, String> revokeContact(Map<String, String> input) {
    String fp = required(input, FINGERPRINT);
    if (!state.containsKey(CONTACT_PREFIX + fp)) throw new MailFailure("unknown-sender-or-contact");
    state.put(REVOKED_PREFIX + fp, "true");
    state.remove(APPROVAL);
    commit();
    return Map.of(STATUS, "contact-revoked");
  }

  /**
   * Protects a bounded draft addressed to an active approved contact.
   *
   * @param input private command fields
   * @return private draft status
   */
  private Map<String, String> saveDraft(Map<String, String> input) {
    String fp = required(input, FINGERPRINT);
    var recipient = approved(fp);
    String subject = required(input, SUBJECT);
    String body = required(input, "body");
    if (subject.getBytes(StandardCharsets.UTF_8).length > 256
        || body.getBytes(StandardCharsets.UTF_8).length > 16384) throw new MailFailure("quota");
    var draft = Map.of(FINGERPRINT, fp, SUBJECT, subject, "body", body);
    String encodedDraft = json(draft);
    var own = contact(state.get(OWN_CARD), true);
    // Reserve the longest allowed timestamp encodings so time alone cannot outgrow admission.
    var message =
        messageFields(draft, recipient, own, "0".repeat(32), Long.MAX_VALUE - 1, Long.MAX_VALUE);
    if (encodedDraft.getBytes(StandardCharsets.UTF_8).length > 32768
        || MailWire.encode(message).length > MAX_COMPOSED_MESSAGE) throw new MailFailure("quota");
    MailWire.messagePayload(message);
    state.put(DRAFT, encodedDraft);
    state.remove(APPROVAL);
    commit();
    return Map.of(STATUS, DRAFT);
  }

  /**
   * Commits approval binding to the exact draft and approved contact.
   *
   * @return exact private preview and approval binding
   */
  private Map<String, String> preview() {
    var draft = fields(required(state, DRAFT), 32768);
    var recipient = approved(draft.get(FINGERPRINT));
    String approval =
        hash(
            (state.get(DRAFT) + state.get(CONTACT_PREFIX + draft.get(FINGERPRINT)))
                .getBytes(StandardCharsets.UTF_8));
    state.put(APPROVAL, approval);
    commit();
    return Map.of(
        STATUS,
        "approval-required",
        APPROVAL,
        approval,
        RECIPIENT_FINGERPRINT,
        recipient.get(RECIPIENT_FINGERPRINT),
        RECIPIENT_EPOCH,
        recipient.get(RECIPIENT_EPOCH),
        SUBJECT,
        draft.get(SUBJECT),
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
    if (!NORMAL.equals(state.get(RECOVERY))) throw new MailFailure("recovery-paused");
    if (count(OUTBOX_PREFIX) >= 8) throw new MailFailure("quota");
    String approval = required(input, APPROVAL);
    if (!approval.equals(state.get(APPROVAL))) throw new MailFailure("approval-required");
    var draft = fields(required(state, DRAFT), 32768);
    var recipient = approved(draft.get(FINGERPRINT));
    var own = contact(state.get(OWN_CARD), true);
    if (!approval.equals(
        hash(
            (state.get(DRAFT) + state.get(CONTACT_PREFIX + draft.get(FINGERPRINT)))
                .getBytes(StandardCharsets.UTF_8)))) throw new MailFailure("approval-required");
    String id = randomId();
    long created = now();
    long expires =
        Math.min(
            created + 30 * DAY,
            Math.min(MailWire.decimal(recipient.get(EXPIRES)), MailWire.decimal(own.get(EXPIRES))));
    var msg = messageFields(draft, recipient, own, id, created, expires);
    byte[] signed = crypto("sign", state.get(SIGNING_ID), MailWire.messagePayload(msg));
    byte[] sealed =
        MailHpke.seal(
            "network",
            recipient.get(RECIPIENT_FINGERPRINT),
            MailWire.unbase64(recipient.get("recipientKey"), 32),
            signed);
    var out = new LinkedHashMap<String, String>();
    out.put(FIELD_STATE, "sealed");
    out.put("contact", draft.get(FINGERPRINT));
    out.put(ENVELOPE, MailWire.base64(sealed));
    out.put("signed", MailWire.base64(signed));
    out.put(REFERENCE, "");
    state.put(OUTBOX_PREFIX + id, json(out));
    state.remove(APPROVAL);
    state.remove(DRAFT);
    commit();
    return publish(id);
  }

  /**
   * Builds the same message fields for encoded draft admission and actual signing.
   *
   * @param draft validated recipient selection and literal content
   * @param recipient approved contact binding
   * @param own local account binding
   * @param id random send identifier, or a same-width placeholder for sizing only
   * @param created creation timestamp
   * @param expires expiry timestamp
   * @return unsigned message fields in wire order
   */
  private static Map<String, String> messageFields(
      Map<String, String> draft,
      Map<String, String> recipient,
      Map<String, String> own,
      String id,
      long created,
      long expires) {
    var msg = new LinkedHashMap<String, String>();
    msg.put("profile", MailWire.MESSAGE);
    msg.put(MESSAGE_ID, id);
    msg.put(SENDER, own.get(SIGNING_FINGERPRINT));
    msg.put("senderAccount", own.get(ACCOUNT));
    msg.put(SENDER_EPOCH, own.get(SIGNING_EPOCH));
    msg.put("recipient", recipient.get(RECIPIENT_FINGERPRINT));
    msg.put("recipientAccount", recipient.get(ACCOUNT));
    msg.put(RECIPIENT_EPOCH, recipient.get(RECIPIENT_EPOCH));
    msg.put(CREATED, Long.toString(created));
    msg.put(EXPIRES, Long.toString(expires));
    msg.put(SUBJECT, draft.get(SUBJECT));
    msg.put("body", draft.get("body"));
    msg.put(FORMAT, "text/plain");
    return msg;
  }

  /**
   * Recovers insertion state and publishes only committed immutable ciphertext.
   *
   * @param operation stable committed outbox operation identifier
   * @return private queued or inserted result
   */
  private Map<String, String> publish(String operation) {
    if (!operation.matches("[0-9a-f]{32}")) throw new MailFailure("invalid");
    var out = fields(required(state, OUTBOX_PREFIX + operation), MAX_STATE);
    if (INSERTED.equals(out.get(FIELD_STATE)))
      return Map.of(STATUS, INSERTED, OPERATION, operation, REFERENCE, out.get(REFERENCE));
    String identifier = "app-document-mail-prototype-" + operation;
    var progress =
        backend.request("GET", "/queue/app-document-status", Map.of(IDENTIFIER, identifier));
    String status = text(progress, FIELD_STATE);
    if (INSERTED.equals(status)) {
      String reference = text(progress, REFERENCE);
      requireChk(reference);
      out.put(FIELD_STATE, INSERTED);
      out.put(REFERENCE, reference);
      state.put(OUTBOX_PREFIX + operation, json(out));
      commit();
      return Map.of(STATUS, INSERTED, OPERATION, operation, REFERENCE, reference);
    }
    if ("failed".equals(status) || "missing".equals(status)) {
      if (!NORMAL.equals(state.get(RECOVERY))) throw new MailFailure("recovery-paused");
      requireUnexpiredOutboxMessage(out);
      approved(required(out, "contact"));
    }
    if ("failed".equals(status)) {
      backend.request("POST", "/queue/restart", Map.of(IDENTIFIER, identifier));
    } else if ("missing".equals(status)) {
      // These committed immutable bytes are the only application bytes ever inserted.
      backend.request(
          "POST",
          "/queue/inserts/app-document",
          Map.of(
              "insertUri",
              "CHK@",
              IDENTIFIER,
              identifier,
              "documentBase64",
              out.get(ENVELOPE),
              "contentType",
              "application/vnd.crypta.mail+json",
              "targetFilename",
              "mail.json"));
    }
    out.put(FIELD_STATE, "queued");
    state.put(OUTBOX_PREFIX + operation, json(out));
    commit();
    return Map.of(
        STATUS,
        "queued",
        OPERATION,
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
    if (MailWire.decimal(message.get(EXPIRES)) <= now()) throw new MailFailure("expired");
  }

  /**
   * Fetches by explicit consent and atomically admits verified mail with replay evidence.
   *
   * @param input private command fields
   * @return bounded acceptance, duplicate or rejection status
   */
  private Map<String, String> receive(Map<String, String> input) {
    if (!"yes".equals(input.get("confirmed"))) throw new MailFailure("network-consent-required");
    if (!NORMAL.equals(state.get(RECOVERY))) throw new MailFailure("recovery-paused");
    if (count(REPLAY_PREFIX) >= 128 || count(INBOX_PREFIX) >= 16) throw new MailFailure("quota");
    String reference = required(input, REFERENCE);
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
                FORMAT,
                "base64",
                "purpose",
                "mail-explicit-import"));
    byte[] envelope = decode(text(response, "contentBase64"), 65536);
    MailHpke.validateNetworkEnvelope(envelope);
    var visibleHeader = MailWire.decode(envelope, 65536);
    var localCard = contact(state.get(OWN_CARD), false);
    if (!localCard.get(RECIPIENT_FINGERPRINT).equals(visibleHeader.get("selector")))
      throw new MailFailure("wrong-recipient");
    byte[] signed = crypto("open", state.get(RECIPIENT_ID), envelope);
    byte[] payload = MailWire.signedPayload(signed);
    var msg = MailWire.decode(payload, 32768);
    MailWire.messagePayload(msg);
    if (!state.containsKey(CONTACT_PREFIX + required(msg, SENDER)))
      throw new MailFailure("unknown-sender");
    var sender = approved(required(msg, SENDER));
    if (!MailWire.verify(
        MailWire.unbase64(sender.get(SIGNING_KEY), 32),
        MailWire.preimage(MailWire.MESSAGE, payload),
        MailWire.signature(signed))) throw new MailFailure("invalid");
    var own = contact(state.get(OWN_CARD), false);
    validateIncomingBindings(msg, sender, own);
    String replay =
        hash(
            (own.get(ACCOUNT)
                    + ":"
                    + own.get(RECIPIENT_FINGERPRINT)
                    + ":"
                    + own.get(RECIPIENT_EPOCH)
                    + ":"
                    + msg.get(SENDER)
                    + ":"
                    + msg.get(SENDER_EPOCH)
                    + ":"
                    + msg.get(MESSAGE_ID))
                .getBytes(StandardCharsets.UTF_8));
    String payloadDigest = hash(payload);
    String previous = state.get(REPLAY_PREFIX + replay);
    if (previous != null)
      return Map.of(STATUS, previous.equals(payloadDigest) ? "duplicate" : "conflict");
    state.put(REPLAY_PREFIX + replay, payloadDigest);
    state.put(INBOX_PREFIX + replay, MailWire.base64(signed));
    commit();
    return Map.of(STATUS, "accepted", MESSAGE_ID, replay, "senderTrust", "locally-pinned");
  }

  /**
   * Checks authenticated account bindings and both contact validity intervals before admission.
   *
   * @param msg complete message fields after signature and sender-pin verification
   * @param sender approved sender contact for the signed account and epoch
   * @param own retained local contact bound to the decryption identity
   * @throws MailFailure if account/key bindings or local timestamp policy reject the message
   */
  private void validateIncomingBindings(
      Map<String, String> msg, Map<String, String> sender, Map<String, String> own) {
    for (String[] pair :
        List.of(
            new String[] {"senderAccount", ACCOUNT}, new String[] {SENDER_EPOCH, SIGNING_EPOCH}))
      if (!msg.get(pair[0]).equals(sender.get(pair[1]))) throw new MailFailure("contact-mismatch");
    if (!msg.get("recipient").equals(own.get(RECIPIENT_FINGERPRINT))
        || !msg.get("recipientAccount").equals(own.get(ACCOUNT))
        || !msg.get(RECIPIENT_EPOCH).equals(own.get(RECIPIENT_EPOCH)))
      throw new MailFailure("wrong-recipient");
    long created = MailWire.decimal(msg.get(CREATED));
    long expires = MailWire.decimal(msg.get(EXPIRES));
    if (created > now() + 300
        || expires <= now()
        || expires - created > 30 * DAY
        || created < MailWire.decimal(sender.get(CREATED))
        || expires > MailWire.decimal(sender.get(EXPIRES))
        || created < MailWire.decimal(own.get(CREATED))
        || expires > MailWire.decimal(own.get(EXPIRES))) throw new MailFailure("expired");
  }

  /**
   * Returns literal content from an already accepted protected local copy.
   *
   * @param input private command fields
   * @return literal verified-local-copy fields
   */
  private Map<String, String> read(Map<String, String> input) {
    String id = required(input, MESSAGE_ID);
    var message =
        MailWire.decode(
            MailWire.signedPayload(decode(required(state, INBOX_PREFIX + id), 45056)), 32768);
    return Map.of(
        STATUS,
        "verified-local-copy",
        SENDER,
        message.get(SENDER),
        SUBJECT,
        message.get(SUBJECT),
        "body",
        message.get("body"),
        FORMAT,
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
    var restored = openState(decode(required(input, BACKUP), 262144));
    if (!current.isEmpty() && !current.get(STORAGE_ID).equals(restored.get(STORAGE_ID)))
      throw new MailFailure("key-unavailable");
    for (var entry : current.entrySet())
      if (entry.getKey().startsWith(REPLAY_PREFIX) || entry.getKey().startsWith(REVOKED_PREFIX)) {
        String old = restored.putIfAbsent(entry.getKey(), entry.getValue());
        if (old != null && !old.equals(entry.getValue())) throw new MailFailure("conflict");
      }
    state = restored;
    state.put(RECOVERY, "paused-after-restore");
    state.remove(APPROVAL);
    validateKeys();
    commit();
    return Map.of(
        STATUS,
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
    result.put(STATUS, "ready");
    result.put(RECOVERY, state.get(RECOVERY));
    if (state.containsKey(INITIALIZATION_RECOVERY_EPOCH)) {
      result.put(INITIALIZATION_RECOVERY_EPOCH, state.get(INITIALIZATION_RECOVERY_EPOCH));
      result.put(
          "note",
          "Resumed setup. Prior replay history cannot be verified if an older raw app-data snapshot"
              + " was restored; this recovery epoch does not prove a new account.");
    }
    result.put("contacts", Long.toString(count(CONTACT_PREFIX)));
    result.put(
        "contactFingerprints",
        String.join(
            ",",
            state.keySet().stream()
                .filter(k -> k.startsWith(CONTACT_PREFIX))
                .map(k -> k.substring(8))
                .toList()));
    result.put("inbox", Long.toString(count(INBOX_PREFIX)));
    result.put("outbox", Long.toString(count(OUTBOX_PREFIX)));
    result.put(
        "messageIds",
        String.join(
            ",",
            state.keySet().stream()
                .filter(k -> k.startsWith(INBOX_PREFIX))
                .map(k -> k.substring(6))
                .toList()));
    result.put(
        "operations",
        String.join(
            ",",
            state.keySet().stream()
                .filter(k -> k.startsWith(OUTBOX_PREFIX))
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
    if (state.containsKey(REVOKED_PREFIX + fp)) throw new MailFailure("contact-revoked");
    String card = state.get(CONTACT_PREFIX + fp);
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
    byte[] wrapper = card.getBytes(StandardCharsets.UTF_8);
    byte[] payload = MailWire.signedPayload(wrapper);
    var contact = MailWire.decode(payload, 4096);
    MailWire.contactPayload(contact);
    if (!MailWire.verify(
        MailWire.unbase64(contact.get(SIGNING_KEY), 32),
        MailWire.preimage(MailWire.CONTACT, payload),
        MailWire.signature(wrapper))) throw new MailFailure("invalid-contact");
    if (active
        && (MailWire.decimal(contact.get(CREATED)) > now() + 300
            || MailWire.decimal(contact.get(EXPIRES)) <= now()))
      throw new MailFailure("expired-contact");
    return contact;
  }

  /** Protects and CAS-publishes the complete dataset with insertion-completion headroom. */
  private void commit() {
    byte[] plaintext = MailWire.encode(state);
    if (plaintext.length + completionReserve() > MAX_STATE || count(REPLAY_PREFIX) > 128)
      throw new MailFailure("quota");
    byte[] envelope = crypto("seal-storage", state.get(STORAGE_ID), plaintext);
    java.util.Arrays.fill(plaintext, (byte) 0);
    var wrapper = new LinkedHashMap<String, String>();
    wrapper.put(STORAGE_ID, state.get(STORAGE_ID));
    wrapper.put(ENVELOPE, MailWire.base64(envelope));
    byte[] value = MailWire.encode(wrapper);
    if (value.length > 262144) throw new MailFailure("quota");
    storeDataset(value);
  }

  /**
   * Publishes setup intent or a protected dataset using the last observed record digest.
   *
   * @param value complete bounded record bytes
   */
  private void storeDataset(byte[] value) {
    var parameters = new LinkedHashMap<String, String>();
    parameters.put("namespace", "mail-state");
    parameters.put("key", "dataset");
    parameters.put("schemaVersion", "1");
    parameters.put("contentType", "application/octet-stream");
    parameters.put("valueBase64", MailWire.base64(value));
    if (digest != null) parameters.put("ifMatchSha256", digest);
    var metadataRecord =
        object(backend.request("POST", "/app-data/records", parameters).get("record"));
    digest = text(metadataRecord, "sha256");
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
      if (entry.getKey().startsWith(OUTBOX_PREFIX)
          && !INSERTED.equals(fields(entry.getValue(), MAX_STATE).get(FIELD_STATE))) bytes += 256;
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
            mail(action, Map.of(IDENTITY_ID, id, "payloadBase64", MailWire.base64(payload))),
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
   * @param value canonical padded Base64 text
   * @param max maximum decoded byte count; the encoded limit is derived from it
   * @return newly decoded bytes
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
   * @param value canonical flat JSON text containing only string fields
   * @param max maximum UTF-8 encoded byte count
   * @return mutable private string fields in input order
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
