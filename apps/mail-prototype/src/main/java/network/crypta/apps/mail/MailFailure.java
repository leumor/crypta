package network.crypta.apps.mail;

/**
 * Worker-internal failure carrying only a fixed local classification.
 *
 * <p>The message is suitable for the own-app status response, not arbitrary exception text. Cause,
 * suppression and stack-trace capture are disabled. Callers must supply a fixed code and must never
 * embed message contents, contact material, keys or CHK references in it.
 */
final class MailFailure extends RuntimeException {
  /**
   * Creates a fixed failure without a cause or stack trace containing endpoint data.
   *
   * @param code fixed local status code selected by worker code, without private values
   */
  MailFailure(String code) {
    super(code, null, false, false);
  }
}
