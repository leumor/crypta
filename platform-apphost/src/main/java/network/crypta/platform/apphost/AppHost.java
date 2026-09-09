package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.apphost.sandbox.AppSandboxPolicy;
import network.crypta.platform.apphost.sandbox.AppSandboxProviders;
import network.crypta.platform.apphost.sandbox.AppSandboxStatus;

/**
 * Transport-neutral host API for locally installed out-of-process applications.
 *
 * <p>{@code AppHost} defines the narrow lifecycle surface that higher-level shells, transports, and
 * future management APIs use to interact with locally installed app bundles. The interface is
 * intentionally conservative for AppHost v1: it installs validated bundles from a caller-supplied
 * staging directory, exposes immutable installation metadata, and manages at most one live child
 * process per installed application identifier.
 *
 * <p>Implementations are responsible for keeping host-owned filesystem layout and runtime state
 * consistent with the returned snapshots. Callers can treat {@link InstalledAppSnapshot} and {@link
 * RunningAppSnapshot} as point-in-time views rather than persistent handles. A later call to {@link
 * #describe(String)}, {@link #status(String)}, or {@link #listRunning()} may therefore reflect
 * newer filesystem or process state than an earlier snapshot.
 */
public interface AppHost {
  /** Default number of process-log bytes returned by bounded log-tail APIs. */
  int DEFAULT_PROCESS_LOG_TAIL_BYTES = 64 * 1024;

  /** Hard maximum number of process-log bytes returned by bounded log-tail APIs. */
  int MAX_PROCESS_LOG_TAIL_BYTES = 1024 * 1024;

  /**
   * Authorizes the exact catalog origin that a rollback would restore.
   *
   * <p>Implementations invoke this callback while holding their lifecycle mutation boundary, after
   * validating the retained bundle and matching its manifest to the rollback-origin slot, but
   * before swapping either bundle or provenance. The returned lease remains held through commit or
   * compensation. While it is held, callers can re-read current local catalog, publisher, and
   * reviewer policy for the exact origin selected by the host. The authorization cannot then be
   * revoked between the check and the durable swap.
   */
  @FunctionalInterface
  interface CatalogRollbackAuthorization {
    /**
     * Authorizes one exact retained catalog origin.
     *
     * @param rollbackOrigin host-owned provenance paired with the retained rollback bundle
     * @return lease retaining the authorization through the coordinated rollback commit
     * @throws IOException if current local policy cannot authenticate or authorize the origin
     */
    CatalogMutationAuthorizationLease authorize(InstalledAppOrigin rollbackOrigin)
        throws IOException;
  }

  /**
   * Authorizes an exact catalog mutation and keeps its local trust decision stable until commit.
   *
   * <p>Implementations invoke this callback while holding their lifecycle mutation boundary and
   * close the returned lease only after bundle and provenance state have either committed together
   * or been compensated. The authorization provider must prevent catalog trust mutations relevant
   * to the approved plan while the lease remains open.
   */
  @FunctionalInterface
  interface CatalogMutationAuthorization {
    /**
     * Authorizes one exact target origin.
     *
     * @param targetOrigin host-owned provenance that will accompany the replacement bundle
     * @return lease retaining the authorization through the coordinated host commit
     * @throws IOException if current local policy cannot authenticate or authorize the target
     */
    CatalogMutationAuthorizationLease authorize(InstalledAppOrigin targetOrigin) throws IOException;
  }

  /** A same-thread lease retaining catalog mutation authorization through an AppHost commit. */
  @FunctionalInterface
  interface CatalogMutationAuthorizationLease extends AutoCloseable {
    /** Releases the retained local trust decision. */
    @Override
    void close();
  }

  /** Coordinates retained catalog revisions with every host-owned provenance slot. */
  interface CatalogOriginRetention {
    /**
     * Ensures that every current or rollback provenance revision is retained before commit.
     *
     * <p>This phase may add retention state but must not release revisions absent from the supplied
     * snapshot: the durable host transaction can still restore its prior provenance.
     *
     * @param retainedOrigins complete current-and-rollback origin snapshot
     * @throws IOException if retention state cannot be reconciled safely
     */
    void retain(List<InstalledAppOrigin> retainedOrigins) throws IOException;

    /**
     * Reconciles retention after provenance reaches its durable commit point.
     *
     * <p>Implementations must treat the supplied list as complete and release revisions absent from
     * it. A failed cleanup remains safe because the retain phase has already protected every live
     * origin; the host retries reconciliation before later persistent work.
     *
     * @param retainedOrigins complete committed current-and-rollback origin snapshot
     * @throws IOException if retention state cannot be reconciled safely
     */
    void reconcile(List<InstalledAppOrigin> retainedOrigins) throws IOException;
  }

  /** Exact current-origin state approved for a coordinated catalog update. */
  final class CatalogOriginExpectation {
    private static final CatalogOriginExpectation ABSENT = new CatalogOriginExpectation(null);

    private final String digestSha256;

    private CatalogOriginExpectation(String digestSha256) {
      this.digestSha256 = digestSha256;
    }

    /** Returns an expectation that no current catalog origin is recorded. */
    public static CatalogOriginExpectation absent() {
      return ABSENT;
    }

    /** Returns an expectation for one exact current catalog-origin digest. */
    public static CatalogOriginExpectation matching(String digestSha256) {
      return new CatalogOriginExpectation(Objects.requireNonNull(digestSha256, "digestSha256"));
    }

    /** Returns the expected digest, or an empty value when absence was approved. */
    public Optional<String> digestSha256() {
      return Optional.ofNullable(digestSha256);
    }

    @Override
    public boolean equals(Object object) {
      return this == object
          || (object instanceof CatalogOriginExpectation other
              && Objects.equals(digestSha256, other.digestSha256));
    }

    @Override
    public int hashCode() {
      return Objects.hashCode(digestSha256);
    }
  }

  /**
   * Default display limit for each managed app {@code process.log} file.
   *
   * <p>Implementations may retain a small additional redaction overlap on disk so bounded log-tail
   * reads can redact tokens and known paths before applying this visible byte limit.
   */
  long DEFAULT_PROCESS_LOG_MAX_BYTES = 1024L * 1024L;

  /**
   * Installs one app from a local staging directory.
   *
   * <p>The staging directory is treated as caller-owned input. Implementations validate the
   * manifest, copy the bundle into host-managed storage, provision any required mutable
   * directories, and return a snapshot that reflects the installed copy rather than the original
   * staging path.
   *
   * @param stagedAppDirectory staging directory containing {@code cryptad-app.properties} and the
   *     files referenced by the manifest
   * @return installed application snapshot describing the copied bundle and derived host paths
   * @throws IOException if validation fails, filesystem boundaries are unsafe, the bundle cannot be
   *     copied, or host-owned directories cannot be provisioned
   */
  InstalledAppSnapshot installFromDirectory(Path stagedAppDirectory) throws IOException;

  /**
   * Installs a catalog bundle and its host-owned origin as one coordinated mutation.
   *
   * <p>The default fails before bundle mutation because a compatibility host cannot promise that
   * bundle and provenance commits are coordinated. Hosts that support catalog installs must
   * override this method and coordinate their native bundle and provenance stores directly.
   *
   * @param stagedAppDirectory verified bundle directory supplied by the catalog planner
   * @param origin exact host-owned provenance for the bundle being installed
   * @return installed snapshot after both bundle and provenance commits succeed
   * @throws IOException if either commit or the required compensation cannot complete safely
   */
  default InstalledAppSnapshot installCatalogFromDirectory(
      Path stagedAppDirectory, InstalledAppOrigin origin) throws IOException {
    Objects.requireNonNull(stagedAppDirectory, "stagedAppDirectory");
    Objects.requireNonNull(origin, "origin");
    throw new AppHostException.CatalogOriginPersistenceUnsupportedException();
  }

  /**
   * Installs a catalog bundle under mutation-scoped current trust authorization.
   *
   * <p>The compatibility default fails closed. Supporting hosts must invoke {@code authorization}
   * inside their lifecycle mutation boundary and retain its returned lease through the coordinated
   * bundle/provenance commit.
   *
   * @param stagedAppDirectory verified bundle directory supplied by the catalog planner
   * @param origin exact host-owned provenance for the bundle being installed
   * @param authorization current local catalog authorization provider
   * @return installed snapshot after both bundle and provenance commits succeed
   * @throws IOException if authorization or either coordinated commit fails
   */
  default InstalledAppSnapshot installCatalogFromDirectory(
      Path stagedAppDirectory,
      InstalledAppOrigin origin,
      CatalogMutationAuthorization authorization)
      throws IOException {
    Objects.requireNonNull(stagedAppDirectory, "stagedAppDirectory");
    Objects.requireNonNull(origin, "origin");
    Objects.requireNonNull(authorization, "authorization");
    throw new AppHostException.CatalogOriginPersistenceUnsupportedException();
  }

  /**
   * Replaces one installed app bundle from a local staging directory.
   *
   * <p>The supplied staging directory is validated using the same caller-owned input rules as
   * installation, but the staged manifest must target the already-installed app being updated.
   * Implementations replace only the immutable installed bundle contents. The host-owned data,
   * cache, and run directories remain attached to the existing app id and are preserved across the
   * update.
   *
   * <p>AppHost v1 keeps update semantics intentionally narrow and explicit: the target app must
   * already be installed and must not be running. Implementations should therefore reject updates
   * for missing or live apps rather than attempting implicit stop/start choreography.
   * Implementations that retain catalog origin provenance must also rotate that provenance with the
   * bundle or reject generic updates while either the current or rollback bundle is origin-tracked;
   * they must never leave catalog provenance attached to unrelated replacement bytes.
   *
   * @param appId stable application identifier
   * @param stagedAppDirectory staging directory containing {@code cryptad-app.properties} and the
   *     files referenced by the manifest
   * @return installed application snapshot describing the replaced bundle and preserved host paths
   * @throws IOException if validation fails, the staged bundle targets a different app id, the app
   *     is missing or still running, or the replacement cannot be completed safely
   */
  InstalledAppSnapshot updateFromDirectory(String appId, Path stagedAppDirectory)
      throws IOException;

  /**
   * Replaces a catalog bundle and rotates its exact origin provenance as one host mutation.
   *
   * <p>The default delegates to the conditional overload, which fails before bundle mutation unless
   * the host explicitly implements coordinated catalog provenance. Production hosts with separate
   * bundle and provenance stores should override the conditional overload so both slots are
   * prepared and compensated under the host's lifecycle lock.
   *
   * @param appId stable identifier of the installed app being replaced
   * @param stagedAppDirectory verified replacement bundle supplied by the catalog planner
   * @param origin exact host-owned provenance for the replacement bundle
   * @return installed snapshot after bundle and provenance reach the same committed revision
   * @throws IOException if replacement, provenance persistence, or compensation fails
   */
  default InstalledAppSnapshot updateCatalogFromDirectory(
      String appId, Path stagedAppDirectory, InstalledAppOrigin origin) throws IOException {
    Optional<String> currentOriginDigest =
        catalogOrigin(appId).map(InstalledAppOrigin::selfDigestSha256);
    CatalogOriginExpectation expectedCurrentOrigin =
        currentOriginDigest
            .map(CatalogOriginExpectation::matching)
            .orElseGet(CatalogOriginExpectation::absent);
    return updateCatalogFromDirectory(appId, stagedAppDirectory, origin, expectedCurrentOrigin);
  }

  /**
   * Conditionally replaces a catalog bundle and its provenance under an exact current-origin
   * expectation.
   *
   * <p>The default fails before bundle mutation because a compatibility host cannot make the
   * expectation check and both commits atomic. Hosts that support catalog updates must override
   * this method and perform all three operations under one lifecycle lock.
   *
   * @param appId stable identifier of the installed app being replaced
   * @param stagedAppDirectory verified replacement bundle supplied by the catalog planner
   * @param origin exact host-owned provenance for the replacement bundle
   * @param expectedCurrentOrigin exact current provenance state approved by the caller
   * @return installed snapshot after bundle and provenance reach the same committed revision
   * @throws IOException if the origin changed, replacement failed, or compensation failed
   */
  default InstalledAppSnapshot updateCatalogFromDirectory(
      String appId,
      Path stagedAppDirectory,
      InstalledAppOrigin origin,
      CatalogOriginExpectation expectedCurrentOrigin)
      throws IOException {
    Objects.requireNonNull(appId, "appId");
    Objects.requireNonNull(stagedAppDirectory, "stagedAppDirectory");
    Objects.requireNonNull(origin, "origin");
    Objects.requireNonNull(expectedCurrentOrigin, "expectedCurrentOrigin");
    throw new AppHostException.CatalogOriginPersistenceUnsupportedException();
  }

  /**
   * Conditionally replaces a catalog bundle under mutation-scoped current trust authorization.
   *
   * <p>The compatibility default fails closed. Supporting hosts must hold the returned
   * authorization lease until the exact bundle and provenance mutation commits or is compensated.
   *
   * @param appId stable identifier of the installed app being replaced
   * @param stagedAppDirectory verified replacement bundle supplied by the catalog planner
   * @param origin exact host-owned provenance for the replacement bundle
   * @param expectedCurrentOrigin exact current provenance state approved by the caller
   * @param authorization current local catalog authorization provider
   * @return installed snapshot after bundle and provenance reach the same committed revision
   * @throws IOException if authorization, replacement, provenance persistence, or compensation
   *     fails
   */
  default InstalledAppSnapshot updateCatalogFromDirectory(
      String appId,
      Path stagedAppDirectory,
      InstalledAppOrigin origin,
      CatalogOriginExpectation expectedCurrentOrigin,
      CatalogMutationAuthorization authorization)
      throws IOException {
    Objects.requireNonNull(appId, "appId");
    Objects.requireNonNull(stagedAppDirectory, "stagedAppDirectory");
    Objects.requireNonNull(origin, "origin");
    Objects.requireNonNull(expectedCurrentOrigin, "expectedCurrentOrigin");
    Objects.requireNonNull(authorization, "authorization");
    throw new AppHostException.CatalogOriginPersistenceUnsupportedException();
  }

  /**
   * Returns path-free metadata for the previous bundle available for rollback.
   *
   * <p>A present value means the host has a durable previous installed bundle for the app id. The
   * returned record is safe for public summaries: it exposes only manifest-level identity and
   * version metadata, never launch tokens or AppHost filesystem paths. New installations have no
   * rollback record until their first successful update.
   *
   * @param appId stable application identifier
   * @return rollback metadata when a previous bundle is available, otherwise {@link
   *     Optional#empty()}
   * @throws IOException if the rollback tree cannot be inspected safely or its manifest is invalid
   */
  default Optional<AppRollbackRecord> rollbackStatus(String appId) throws IOException {
    Objects.requireNonNull(appId, "appId");
    return Optional.empty();
  }

  /**
   * Restores the previous installed bundle for one stopped app.
   *
   * <p>The operation replaces only the immutable installed bundle. The app's host-owned data,
   * cache, and run directories remain attached to the app id and are preserved. Implementations
   * must reject live apps rather than replacing files beneath a running process.
   *
   * @param appId stable application identifier
   * @return installed application snapshot after the previous bundle has been restored
   * @throws IOException if the app is missing, running, has no rollback record, or the replacement
   *     cannot be completed safely
   */
  default InstalledAppSnapshot rollback(String appId) throws IOException {
    Objects.requireNonNull(appId, "appId");
    throw new UnsupportedOperationException("rollback is not supported by this AppHost");
  }

  /**
   * Restores a retained bundle only after authorizing its exact catalog provenance.
   *
   * <p>The default fails closed because a compatibility host cannot promise that provenance
   * selection and authorization occur inside one lifecycle lock. Hosts that persist catalog origins
   * should override this method. Legacy callers may continue to use {@link #rollback(String)} only
   * when the retained rollback bundle has no persisted catalog provenance.
   *
   * @param appId stable application identifier
   * @param authorization callback that revalidates the host-selected rollback origin
   * @return installed application snapshot after rollback
   * @throws IOException if authorization, validation, or rollback fails
   */
  default InstalledAppSnapshot rollback(String appId, CatalogRollbackAuthorization authorization)
      throws IOException {
    Objects.requireNonNull(appId, "appId");
    Objects.requireNonNull(authorization, "authorization");
    throw new UnsupportedOperationException(
        "authorized catalog rollback is not supported by this AppHost");
  }

  /**
   * Persists host-owned catalog origin provenance after a catalog install or update commits.
   *
   * <p>The default fails closed. Implementations must not accept a federated catalog bundle unless
   * they can persist its origin, and callers should prefer the coordinated catalog install/update
   * methods instead of committing these states separately.
   */
  default void recordCatalogOrigin(InstalledAppOrigin origin) throws IOException {
    Objects.requireNonNull(origin, "origin");
    throw new AppHostException.CatalogOriginPersistenceUnsupportedException();
  }

  /** Returns path-free catalog origin provenance for an installed app, when recorded. */
  default Optional<InstalledAppOrigin> catalogOrigin(String appId) throws IOException {
    Objects.requireNonNull(appId, "appId");
    return Optional.empty();
  }

  /**
   * Reports whether the retained rollback bundle carries catalog provenance requiring current local
   * authorization.
   *
   * <p>The compatibility default is conservative for hosts that expose only a current catalog
   * origin: a present current origin requires the authorized rollback overload. Hosts that maintain
   * distinct current and rollback provenance slots should override this method and inspect the
   * exact rollback slot. A pre-federation host whose default {@link #catalogOrigin(String)} is
   * empty continues to use {@link #rollback(String)}.
   *
   * @param appId stable application identifier
   * @return {@code true} when rollback must use {@link #rollback(String,
   *     CatalogRollbackAuthorization)}
   * @throws IOException if provenance state cannot be inspected safely
   */
  default boolean rollbackRequiresCatalogAuthorization(String appId) throws IOException {
    Objects.requireNonNull(appId, "appId");
    return catalogOrigin(appId).isPresent();
  }

  /**
   * Removes one installed app and its host-owned directories.
   *
   * <p>This operation removes both the immutable installed bundle and the mutable per-app data,
   * cache, and run directories that belong to the host layout. Implementations are expected to
   * reject removal while the app is still running, so callers do not delete files out from under a
   * live child process.
   *
   * @param appId stable application identifier
   * @throws IOException if the app is still running, is not installed, or any owned files cannot be
   *     removed cleanly
   */
  void uninstall(String appId) throws IOException;

  /**
   * Removes one installed app using explicit operator cleanup options.
   *
   * <p>The default implementation preserves existing {@link #uninstall(String)} behavior for
   * implementations that have not added preserve-data support. Implementations that can keep
   * persistent app data while removing the immutable bundle should override this method and honor
   * {@link AppUninstallOptions#preserveData()}.
   *
   * @param appId stable application identifier
   * @param options explicit uninstall cleanup options
   * @throws IOException if the app is still running, is not installed, or owned files cannot be
   *     removed cleanly
   */
  default void uninstall(String appId, AppUninstallOptions options) throws IOException {
    Objects.requireNonNull(options, "options");
    if (options.preserveData()) {
      throw new AppHostException("preserve-data uninstall is not supported");
    }
    uninstall(appId);
  }

  /**
   * Lists all installed apps.
   *
   * <p>The returned list is a fresh filesystem-backed snapshot. Callers should not assume the list
   * remains current after the method returns, especially if another actor is installing or
   * uninstalling applications concurrently.
   *
   * @return installed application snapshots sorted by app id
   * @throws IOException if the installed-app tree cannot be scanned, or one of the installed
   *     manifests cannot be read safely
   */
  List<InstalledAppSnapshot> listInstalled() throws IOException;

  /**
   * Describes one installed app.
   *
   * @param appId stable application identifier
   * @return installed snapshot when the application is present, or {@link Optional#empty()} when it
   *     is not installed
   * @throws IOException if the installed-app tree cannot be read safely or the installed manifest
   *     is invalid
   */
  Optional<InstalledAppSnapshot> describe(String appId) throws IOException;

  /**
   * Runs a bounded local data operation while the exact signed installed bundle cannot change.
   *
   * <p>The host revalidates historical signature trust before invoking the action. Implementations
   * must serialize this action with bundle replacement, rollback, and uninstall. The conservative
   * default rejects the operation; describing an app alone does not provide a mutation lease.
   *
   * @param appId installed app identifier
   * @param action local operation, which must not launch processes or mutate the host lifecycle
   * @param <T> operation result type
   * @return the action result
   * @throws IOException if signature verification or the guarded action fails
   */
  default <T> T withVerifiedInstalledBundle(String appId, VerifiedBundleAction<T> action)
      throws IOException {
    throw new IOException("Verified installed-bundle guard is unavailable.");
  }

  /** Local operation invoked under the host's verified installed-bundle mutation guard. */
  @FunctionalInterface
  interface VerifiedBundleAction<T> {
    /**
     * Executes against the freshly verified installed snapshot.
     *
     * @param installed immutable installed manifest and internal paths
     * @param verification authenticated path-free signing identity
     * @return local operation result
     * @throws IOException if the local operation cannot complete
     */
    T run(
        InstalledAppSnapshot installed,
        network.crypta.platform.appdist.AppBundleVerification verification)
        throws IOException;
  }

  /**
   * Starts one installed app as a child process.
   *
   * <p>Implementations are expected to validate the installed bundle again at launch time, create
   * or refresh runtime directories, start the child process, and return a snapshot that includes a
   * fresh launch token and representative process identifier. A successful return means the host
   * considers the app running and manageable through {@link #status(String)} and {@link
   * #stop(String)}.
   *
   * @param appId stable application identifier
   * @return running snapshot including the fresh launch token and launch timestamp
   * @throws IOException if the app is not installed, is already running, or the child process
   *     cannot be launched and tracked successfully
   */
  RunningAppSnapshot start(String appId) throws IOException;

  /**
   * Stops one running app if it is active.
   *
   * <p>A return value of {@code false} means the host had no live process to stop at the time of
   * the call. A return value of {@code true} means the host successfully transitioned a running app
   * to the stopped state. Implementations may use graceful termination followed by escalation, but
   * they should not report success while a recovered child process is still running.
   *
   * @param appId stable application identifier
   * @return {@code true} when a running process was found and stopped; {@code false} when no live
   *     process was present
   * @throws IOException if a running app cannot be stopped cleanly within the implementation's
   *     shutdown policy
   */
  boolean stop(String appId) throws IOException;

  /**
   * Returns the current live process snapshot, if any.
   *
   * @param appId stable application identifier
   * @return running snapshot when the app is still tracked as live, or {@link Optional#empty()}
   *     when it is not currently running
   */
  Optional<RunningAppSnapshot> status(String appId);

  /**
   * Lists all live child processes.
   *
   * <p>The returned list is a point-in-time runtime view. It is sorted by app id to give callers a
   * stable ordering for display, polling, and test assertions.
   *
   * @return immutable list of running snapshots sorted by app id
   */
  List<RunningAppSnapshot> listRunning();

  /**
   * Returns the provider-aware inactive sandbox status for an installed manifest policy.
   *
   * <p>Inventory and app-detail summaries call this before a process has been launched, or after a
   * process has stopped, so operator-facing status reflects the host's configured provider
   * selection instead of a policy-only default. Implementations with explicit provider registries
   * should override this method. The default remains conservative for tests and alternate
   * embeddings that do not expose provider configuration.
   *
   * @param policy requested sandbox policy from an installed manifest
   * @return token-free inactive sandbox status safe for public summaries
   */
  default AppSandboxStatus inactiveSandboxStatus(AppSandboxPolicy policy) {
    return AppSandboxProviders.inactiveStatus(policy);
  }

  /**
   * Authenticates a bearer launch token against the host's current live app state.
   *
   * <p>Blank, unknown, stopped, and stale launch tokens must not authenticate. Successful
   * authentication returns a token-free principal containing the running app id and a sorted,
   * immutable copy of its manifest permissions. Implementations must never return or expose the raw
   * token through the principal.
   *
   * @param token opaque launch token presented by an app process
   * @return token-free principal when the token belongs to a currently running app, or {@link
   *     Optional#empty()} otherwise
   */
  default Optional<AppTokenPrincipal> authenticateLaunchToken(String token) {
    return Optional.empty();
  }

  /**
   * Returns current token-free launch binding, or empty for stopped/unsupported hosts.
   *
   * @param appId installed application identifier
   * @return live launch binding
   */
  default Optional<AppTokenPrincipal> currentLaunch(String appId) {
    return Optional.empty();
  }

  /**
   * Returns token-free process runtime status for one installed app.
   *
   * <p>The status is process-observed only. It does not perform app-provided HTTP health checks or
   * expose launch tokens, data/cache/run paths, or other host filesystem locations.
   *
   * @param appId stable application identifier
   * @return token-free runtime status snapshot
   * @throws IOException if the app is not installed or the host cannot inspect its runtime files
   */
  AppRuntimeStatusSnapshot runtimeStatus(String appId) throws IOException;

  /**
   * Lists token-free runtime status for all installed apps.
   *
   * @return immutable runtime status snapshots sorted by app id
   * @throws IOException if the installed-app tree cannot be scanned
   */
  @SuppressWarnings("unused")
  List<AppRuntimeStatusSnapshot> listRuntimeStatus() throws IOException;

  /**
   * Returns a bounded, token-redacted tail of one app's combined process output log.
   *
   * <p>Implementations must clamp the requested byte bound to {@link #MAX_PROCESS_LOG_TAIL_BYTES},
   * redact launch tokens from returned text, and avoid exposing the runtime log path.
   *
   * @param appId stable application identifier
   * @param maxBytes requested maximum bytes to read before clamping
   * @return token-redacted process-log snapshot
   * @throws IOException if the app is not installed or the log cannot be inspected safely
   */
  AppProcessLogSnapshot readProcessLogTail(String appId, int maxBytes) throws IOException;
}
