/**
 * Fixed transient mediation for the experimental out-of-process Mail application.
 *
 * <p>The broker binds bounded own-app commands and replies to a current AppHost launch and bundle
 * version. Its caller supplies centrally authenticated browser/process identity and capability
 * checks. Frames are private, expire locally and are never durable mailbox state.
 *
 * <p>This package supplies neither generic RPC nor an external consumer service. The app worker
 * owns mailbox behavior; process unavailability cannot fall back to a daemon mailbox engine.
 */
package network.crypta.platform.api.mail;
