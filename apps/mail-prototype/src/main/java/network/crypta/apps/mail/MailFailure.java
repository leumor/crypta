package network.crypta.apps.mail;

/** Fixed local failure classification, without plaintext or cryptographic exception details. */
final class MailFailure extends RuntimeException {
  /**
   * Creates a fixed failure without a cause or stack trace containing endpoint data.
   *
   * @param code bounded public classification selected by worker code
   */
  MailFailure(String code) {
    super(code, null, false, false);
  }
}
