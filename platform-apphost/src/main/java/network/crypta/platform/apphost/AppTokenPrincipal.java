package network.crypta.platform.apphost;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Token-free identity derived from a live AppHost launch token.
 *
 * <p>The principal intentionally carries only stable app identity and manifest-declared
 * permissions. It never stores the raw launch token, so diagnostic strings and downstream
 * authorization decisions cannot accidentally expose bearer credentials.
 *
 * <p>{@link AppHost#authenticateLaunchToken(String)} returns this value after it confirms that a
 * presented token belongs to a currently running app. The Platform API bridge can then convert it
 * into its transport-neutral principal model without learning AppHost internals or returning the
 * token to JSON surfaces. Permissions are sorted to make authorization decisions, logs, and tests
 * deterministic.
 *
 * @param appId stable application identifier for the currently running app
 * @param launchId token-free unique launch generation, empty for legacy principals
 * @param appVersion verified launched version, empty for legacy principals
 * @param permissions immutable manifest permission list sorted lexicographically
 */
public record AppTokenPrincipal(
    String appId, List<String> permissions, String launchId, String appVersion) {
  /**
   * Creates a legacy principal without authority over a private worker channel.
   *
   * @param appId application identifier
   * @param permissions declared permissions
   */
  public AppTokenPrincipal(String appId, List<String> permissions) {
    this(appId, permissions, "", "");
  }

  /**
   * Creates a principal with a normalized, immutable permission view.
   *
   * <p>The constructor rejects blank app ids and copies the permission stream into sorted immutable
   * order. It does not validate permission names against the Platform API capability matrix; that
   * remains the router's responsibility because manifests may contain permissions for other
   * app-host features.
   *
   * @param appId stable application identifier for the authenticated app process
   * @param launchId token-free launch generation
   * @param appVersion verified launched version
   * @param permissions manifest permission list captured from the running app snapshot
   * @throws IllegalArgumentException if {@code appId} is blank
   * @throws NullPointerException if {@code appId}, {@code permissions}, or a permission element is
   *     {@code null}
   */
  public AppTokenPrincipal {
    Objects.requireNonNull(launchId, "launchId");
    Objects.requireNonNull(appVersion, "appVersion");
    Objects.requireNonNull(appId, "appId");
    Objects.requireNonNull(permissions, "permissions");
    if (appId.isBlank()) {
      throw new IllegalArgumentException("appId must not be blank");
    }
    permissions = permissions.stream().sorted(Comparator.naturalOrder()).toList();
  }
}
