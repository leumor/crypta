package network.crypta.platform.api.contentformats;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.crypt.mail.MailHpke;

/**
 * Registry of Crypta app ecosystem content format profiles used by first-party apps.
 *
 * <p>The registry deliberately covers content documents rather than Platform API routes. Stable
 * route compatibility is still governed by the Platform API contract and compatibility-window
 * policy. These descriptors let Java code, SDK mirrors, reference apps, docs, and release
 * certification agree on identifiers, MIME types, filenames, signing domains, byte limits, and
 * version policy. New code should read profile metadata from this class instead of copying literals
 * into handlers or release probes.
 *
 * <p>The registry is deterministic and immutable. Profile order is stable for docs and evidence
 * generation, and lookup by id is exact so future major versions are not silently treated as v1
 * documents.
 */
public final class ContentFormatProfileRegistry {
  /**
   * Profile document schema and signed document root identifier.
   *
   * <p>This value appears in profile payloads and signed profile roots. AppVault builders and SDK
   * mirrors use it as the v1 profile document identity rather than deriving it from MIME type.
   */
  public static final String PROFILE_DOCUMENT_ID = "crypta.profile.v1";

  /**
   * MIME type used for published profile documents.
   *
   * <p>Generated profile inserts advertise this content type so fetchers and reference apps can
   * distinguish profile documents from generic JSON without reading private AppVault state.
   */
  public static final String PROFILE_DOCUMENT_CONTENT_TYPE = "application/vnd.crypta.profile+json";

  /**
   * Default generated profile document target filename.
   *
   * <p>Profile Publisher uses this stable filename for generated-document inserts. The value is
   * metadata only and does not expose an insert URI or any local path.
   */
  public static final String PROFILE_DOCUMENT_DEFAULT_FILENAME = "profile.json";

  /**
   * Fixed AppVault purpose used when signing profile payload bytes.
   *
   * <p>The profile signing contract signs the canonical profile payload under this purpose. It is
   * distinct from the document id to preserve the existing Profile Publisher signing behavior.
   */
  public static final String PROFILE_DOCUMENT_SIGNING_PURPOSE = "profile.publish.v1";

  /**
   * Feed snapshot document type.
   *
   * <p>Feed Reader uses this value for canonical snapshots generated from fetched feed entries. Raw
   * RSS, Atom, or text feeds are parsed separately and are not claimed as this profile until a
   * bounded snapshot is generated.
   */
  public static final String FEED_SNAPSHOT_ID = "crypta.feed.snapshot.v1";

  /**
   * MIME type used for feed snapshot generated documents.
   *
   * <p>The generated snapshot route uses this type when publishing deterministic feed summaries. It
   * does not make arbitrary fetched feed bodies part of the profile contract.
   */
  public static final String FEED_SNAPSHOT_CONTENT_TYPE = "application/vnd.crypta.feed+json";

  /**
   * Default generated feed snapshot target filename.
   *
   * <p>This filename is the app-generated insert target for Feed Reader snapshots. It is a content
   * profile default, not a filesystem path recorded in diagnostics.
   */
  public static final String FEED_SNAPSHOT_DEFAULT_FILENAME = "feed.json";

  /**
   * Trust statement document type and signing domain.
   *
   * <p>The trust graph signs bytes under this same domain, so drift between parser metadata and
   * verifier metadata is release-critical. Future major versions must use a different profile id.
   */
  public static final String TRUST_STATEMENT_ID = "crypta.trust.statement.v1";

  /**
   * MIME type used for trust statement generated documents.
   *
   * <p>Trust statement fetchers and import previews use this content type for v1 trust documents.
   * The raw statement body is never required in release evidence for the profile.
   */
  public static final String TRUST_STATEMENT_CONTENT_TYPE = "application/vnd.crypta.trust+json";

  /**
   * Default generated trust statement target filename.
   *
   * <p>Trust Graph preview and publishing flows use this conventional filename for generated
   * statements. It remains stable so app bundles and docs can avoid duplicating string literals.
   */
  public static final String TRUST_STATEMENT_DEFAULT_FILENAME = "trust.json";

  /**
   * Social message document type and signing domain.
   *
   * <p>AppVault social message signing and Social Inbox verification both domain-separate canonical
   * message bytes with this value. Unsupported major versions must be rejected before scoring.
   */
  public static final String SOCIAL_MESSAGE_ID = "crypta.social.message.v1";

  /**
   * Social outbox snapshot document type.
   *
   * <p>Social Inbox uses this value for bounded outbox documents that contain signed v1 social
   * message entries. The outbox itself is an unsigned snapshot profile.
   */
  public static final String SOCIAL_OUTBOX_ID = "crypta.social.outbox.v1";

  /**
   * MIME type used for social outbox generated documents.
   *
   * <p>Generated social outbox inserts advertise this content type so consumers can distinguish
   * outbox snapshots from individual signed social message envelopes.
   */
  public static final String SOCIAL_OUTBOX_CONTENT_TYPE =
      "application/vnd.crypta.social.outbox+json";

  /**
   * Default generated social outbox target filename.
   *
   * <p>This is the conventional target filename for Social Inbox outbox snapshots. It is safe to
   * include in docs and evidence because it contains no operator-local path information.
   */
  public static final String SOCIAL_OUTBOX_DEFAULT_FILENAME = "social-outbox.json";

  /**
   * Shared v1 full-document byte cap for generated app documents.
   *
   * <p>This value matches the app-document insert route cap, so profile-valid generated snapshots
   * are also publishable through the current first-party route.
   */
  public static final int DEFAULT_APP_DOCUMENT_MAX_BYTES = 64 * 1024;

  /**
   * Default byte cap inherited from the bounded foreground content fetch route.
   *
   * <p>Apps may use this broader cap while fetching raw remote content before they know whether the
   * body is a canonical profile document or a source document such as RSS or Atom.
   */
  public static final int FETCHED_DOCUMENT_MAX_BYTES = 262_144;

  /**
   * Byte cap for v1 signed profile, trust, and social canonical payloads.
   *
   * <p>The cap applies to the canonical bytes that enter a signature operation, not necessarily to
   * the surrounding signed document envelope.
   */
  public static final int DEFAULT_SIGNED_PAYLOAD_MAX_BYTES = 32 * 1024;

  /**
   * Canonical profile descriptor.
   *
   * <p>The descriptor keeps Profile Publisher, AppVault signing, SDK metadata, and release evidence
   * aligned on the profile schema, signing purpose, MIME type, and byte limits.
   */
  public static final ContentFormatProfile PROFILE_DOCUMENT =
      new ContentFormatProfile(
          PROFILE_DOCUMENT_ID,
          1,
          PROFILE_DOCUMENT_CONTENT_TYPE,
          PROFILE_DOCUMENT_DEFAULT_FILENAME,
          ContentFormatProfileStatus.EXPERIMENTAL,
          DEFAULT_APP_DOCUMENT_MAX_BYTES,
          DEFAULT_SIGNED_PAYLOAD_MAX_BYTES,
          true,
          PROFILE_DOCUMENT_SIGNING_PURPOSE,
          "profile_payload_json",
          ContentFormatVersionPolicy.CONSERVATIVE_V1,
          null);

  /**
   * Canonical feed snapshot descriptor.
   *
   * <p>The descriptor represents generated snapshots only. Feed Reader can still fetch larger raw
   * feed sources under fetch bounds before it emits a bounded v1 snapshot.
   */
  public static final ContentFormatProfile FEED_SNAPSHOT =
      new ContentFormatProfile(
          FEED_SNAPSHOT_ID,
          1,
          FEED_SNAPSHOT_CONTENT_TYPE,
          FEED_SNAPSHOT_DEFAULT_FILENAME,
          ContentFormatProfileStatus.STABLE,
          DEFAULT_APP_DOCUMENT_MAX_BYTES,
          null,
          false,
          null,
          "deterministic_snapshot_json",
          ContentFormatVersionPolicy.CONSERVATIVE_V1,
          null);

  /**
   * Canonical trust statement descriptor.
   *
   * <p>The descriptor mirrors the trust graph document type and signing domain so canonicalizer,
   * parser, verifier, SDK, and release certification checks cannot drift unnoticed.
   */
  public static final ContentFormatProfile TRUST_STATEMENT =
      new ContentFormatProfile(
          TRUST_STATEMENT_ID,
          1,
          TRUST_STATEMENT_CONTENT_TYPE,
          TRUST_STATEMENT_DEFAULT_FILENAME,
          ContentFormatProfileStatus.EXPERIMENTAL,
          DEFAULT_APP_DOCUMENT_MAX_BYTES,
          DEFAULT_SIGNED_PAYLOAD_MAX_BYTES,
          true,
          TRUST_STATEMENT_ID,
          "domain_separator_newline_canonical_payload_json",
          ContentFormatVersionPolicy.CONSERVATIVE_V1,
          null);

  /**
   * Canonical social message descriptor.
   *
   * <p>Social messages are signed JSON envelopes rather than app-generated document inserts, so the
   * descriptor uses generic JSON content type while preserving strict v1 signing metadata.
   */
  public static final ContentFormatProfile SOCIAL_MESSAGE =
      new ContentFormatProfile(
          SOCIAL_MESSAGE_ID,
          1,
          "application/json",
          null,
          ContentFormatProfileStatus.EXPERIMENTAL,
          DEFAULT_APP_DOCUMENT_MAX_BYTES,
          DEFAULT_SIGNED_PAYLOAD_MAX_BYTES,
          true,
          SOCIAL_MESSAGE_ID,
          "domain_separator_newline_canonical_message_json",
          ContentFormatVersionPolicy.CONSERVATIVE_V1,
          null);

  /**
   * Canonical social outbox descriptor.
   *
   * <p>The descriptor covers generated outbox snapshots that aggregate bounded signed social
   * message entries. It does not broaden the individual message signing contract.
   */
  public static final ContentFormatProfile SOCIAL_OUTBOX =
      new ContentFormatProfile(
          SOCIAL_OUTBOX_ID,
          1,
          SOCIAL_OUTBOX_CONTENT_TYPE,
          SOCIAL_OUTBOX_DEFAULT_FILENAME,
          ContentFormatProfileStatus.EXPERIMENTAL,
          DEFAULT_APP_DOCUMENT_MAX_BYTES,
          null,
          false,
          null,
          "deterministic_outbox_json_with_signed_message_entries",
          ContentFormatVersionPolicy.CONSERVATIVE_V1,
          null);

  /**
   * Experimental ciphertext-only Mail envelope descriptor.
   *
   * <p>The outer envelope is authenticated by HPKE, not an outer sender signature. The encrypted
   * inner message carries a separate Mail-specific signature verified against a pinned contact.
   * Exact framing and limits are specified in {@code docs/mail-wire-specification.md}. This
   * additive profile is not part of the original five-profile trust/social retention review.
   */
  public static final ContentFormatProfile MAIL_ENVELOPE =
      new ContentFormatProfile(
          MailHpke.NETWORK_PROFILE,
          1,
          "application/vnd.crypta.mail+json",
          "mail-envelope.json",
          ContentFormatProfileStatus.EXPERIMENTAL,
          MailHpke.MAX_NETWORK_ENVELOPE_BYTES,
          null,
          false,
          null,
          "strict_flat_json_hpke_authenticated_header",
          ContentFormatVersionPolicy.CONSERVATIVE_V1,
          null);

  private static final List<ContentFormatProfile> PROFILES =
      List.of(
          PROFILE_DOCUMENT,
          FEED_SNAPSHOT,
          TRUST_STATEMENT,
          SOCIAL_MESSAGE,
          SOCIAL_OUTBOX,
          MAIL_ENVELOPE);

  private static final Map<String, ContentFormatProfile> BY_ID =
      Map.of(
          PROFILE_DOCUMENT.id(),
          PROFILE_DOCUMENT,
          FEED_SNAPSHOT.id(),
          FEED_SNAPSHOT,
          TRUST_STATEMENT.id(),
          TRUST_STATEMENT,
          SOCIAL_MESSAGE.id(),
          SOCIAL_MESSAGE,
          SOCIAL_OUTBOX.id(),
          SOCIAL_OUTBOX,
          MAIL_ENVELOPE.id(),
          MAIL_ENVELOPE);

  private ContentFormatProfileRegistry() {}

  /**
   * Returns all registered first-party content profiles in deterministic order.
   *
   * <p>The returned list is immutable and ordered as profile, feed, trust, social message, and
   * social outbox, followed by the additive experimental Mail envelope. Release evidence and
   * documentation checks use the stable order for reproducible summaries; callers should not infer
   * lifecycle priority from the order.
   *
   * @return immutable registry profile list in stable evidence order
   */
  public static List<ContentFormatProfile> profiles() {
    return PROFILES;
  }

  /**
   * Looks up one profile by canonical id.
   *
   * <p>Lookup is exact and case-sensitive. Unknown major versions, alternate aliases, and legacy
   * plugin protocol names return an empty result so callers can report {@code unsupported_version}
   * or equivalent safe diagnostics rather than attempting migration implicitly.
   *
   * @param id content profile id or document type from parsed redaction-safe metadata
   * @return profile descriptor when registered, otherwise an empty result
   */
  @SuppressWarnings("unused")
  public static Optional<ContentFormatProfile> findById(String id) {
    return Optional.ofNullable(BY_ID.get(id));
  }
}
