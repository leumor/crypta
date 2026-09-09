/**
 * Experimental out-of-process Mail with explicit one-recipient plain-text CHK handoff.
 *
 * <p>The AppHost-managed worker owns contacts, approvals, retry state and replay decisions. It
 * persists one bounded, vault-protected app-data dataset and uses the existing insertion/fetch
 * routes only after explicit user commands. Private keys remain in typed vault operations; ordinary
 * app-data records contain protected state rather than plaintext contacts or messages.
 *
 * <p>UI results and transport requests can contain sensitive data and must stay on the
 * authenticated own-app channel. Backups contain data, not vault keys, and restore pauses new
 * sending/receiving. There is no automatic inbox discovery, delivery guarantee or independent
 * security certification.
 */
package network.crypta.apps.mail;
