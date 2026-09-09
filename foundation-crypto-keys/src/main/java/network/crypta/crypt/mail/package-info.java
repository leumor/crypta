/**
 * Fixed experimental Mail wire framing and maintained-library cryptographic primitives.
 *
 * <p>{@link network.crypta.crypt.mail.MailWire} defines canonical string-only objects and pure
 * Ed25519 application framing. {@link network.crypta.crypt.mail.MailHpke} uses a single RFC 9180
 * base-mode suite with separate network and local-storage domains. These leaf primitives neither
 * grant app authority nor decide whether a contact is trusted.
 *
 * <p>Callers must enforce retained-key custody, explicit contact approval, recipient/time policy
 * and durable replay handling. The composition does not provide anonymity or forward secrecy
 * against recipient-key compromise, and it is not an externally audited mail protocol.
 */
package network.crypta.crypt.mail;
