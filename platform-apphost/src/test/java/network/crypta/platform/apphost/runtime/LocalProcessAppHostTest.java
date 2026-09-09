package network.crypta.platform.apphost.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import network.crypta.fs.AppEnv;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppBundleVerification;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.AppSandboxMode;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.AppHostTokenRedactor;
import network.crypta.platform.apphost.AppInstallVerificationPolicy;
import network.crypta.platform.apphost.AppProcessLogSnapshot;
import network.crypta.platform.apphost.AppRollbackRecord;
import network.crypta.platform.apphost.AppRuntimeState;
import network.crypta.platform.apphost.AppRuntimeStatusSnapshot;
import network.crypta.platform.apphost.AppTokenPrincipal;
import network.crypta.platform.apphost.AppUninstallOptions;
import network.crypta.platform.apphost.FileInstalledAppOriginStore;
import network.crypta.platform.apphost.InstalledAppOrigin;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.OwnerOnlyFilePermissions;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestException;
import network.crypta.platform.apphost.sandbox.AppSandboxException;
import network.crypta.platform.apphost.sandbox.AppSandboxLaunchContext;
import network.crypta.platform.apphost.sandbox.AppSandboxLaunchPlan;
import network.crypta.platform.apphost.sandbox.AppSandboxPolicy;
import network.crypta.platform.apphost.sandbox.AppSandboxProvider;
import network.crypta.platform.apphost.sandbox.AppSandboxProviders;
import network.crypta.platform.apphost.sandbox.AppSandboxStatus;
import network.crypta.platform.apphost.sandbox.AppSandboxSupportLevel;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalProcessAppHostTest {
  private static final String SAMPLE_APP_ID = "sample-app";
  private static final String RUNNER_APP_ID = "runner-app";
  private static final String DUPLICATE_APP_ID = "duplicate-app";
  private static final String TEST_KEY_ID = "test-ed25519";
  private static final String MIXED_CASE_APP_ID = "MixedCase-App";
  private static final String NORMALIZED_MIXED_CASE_APP_ID = "mixedcase-app";
  private static final String PYTHON_DAEMON_APP_ID = "python-daemon-app";
  private static final String APP_VERSION = "2.0.0";
  private static final String UPDATED_APP_VERSION = "3.0.0";
  private static final String SECOND_UPDATED_APP_VERSION = "4.0.0";
  private static final String EXIT_ZERO_SCRIPT = "#!/bin/sh\nexit 0\n";
  private static final String UPDATED_BUNDLE_SCRIPT =
      """
      #!/bin/sh
      printf 'new\\n'
      """;
  private static final String PRESERVED_DATA_CONTENT = "keep-data";
  private static final String PRESERVED_CACHE_CONTENT = "keep-cache";
  private static final String PRESERVED_RUN_CONTENT = "keep-run";
  private static final String APPROVED_PUBLISHER_KEY_ID = "publisher-approved";
  private static final String SUBSTITUTED_PUBLISHER_KEY_ID = "publisher-substituted";
  private static final String RESTART_COUNT_FILE_NAME = "restart-count.txt";
  private static final String BUBBLEWRAP_PROVIDER_NAME = "bubblewrap";
  private static final String DEFAULT_TOKEN = "token";
  private static final String APP_TOKEN_ENV_NAME = "CRYPTAD_APP_TOKEN";
  private static final String APP_TOKEN_ENV_ASSIGNMENT_PREFIX = APP_TOKEN_ENV_NAME + "=";
  private static final String REDACTION_PROBE_VALUE = "0123456789abcdef".repeat(4);
  private static final String CACHE_DIR_NAME = "cache";
  private static final String INSTALLED_DIR_NAME = "installed";
  private static final String STAGE_UPDATE_DIR_NAME = "stage-update";
  private static final String INSTALLED_APPS_DIR_SYMLINK_MESSAGE =
      "installedAppsDir must not be a symlink";
  private static final String CONTENT_FILE_NAME = "content.txt";
  private static final String NEW_BUNDLE_FILE_NAME = "new-bundle.txt";
  private static final String NEW_BUNDLE_CONTENT = "new-bundle\n";
  private static final String PROCESS_LOG_FILE_NAME = "process.log";
  private static final String SIGNED_BUNDLE_REQUIRED_MESSAGE =
      "signed app bundle verification is required";
  private static final String POSIX_LAUNCH_PATH = "bin/launch";
  private static final String STARTUP_EXIT_MESSAGE_PREFIX = "app exited during startup: ";
  private static final String RESTART_STORM_WARNING =
      "Automatic restart suppressed after 1 attempts within 300000 ms.";
  private static final String WINDOWS_11 = "Windows 11";
  private static final String LINUX_OS_NAME = "Linux";
  private static final String PYTHON3_COMMAND = "python3";
  private static final String SYSTEM_ENV_COMMAND = "/usr/bin/env";
  private static final String CHILD_SCRIPT_PATH = "bin/child.sh";
  private static final String CHILD_PID_FILE_NAME = "child.pid";
  private static final String WINDOWS_CHILD_EXECUTABLE = "child.exe";
  private static final String POSIX_START_PATH = "bin/start";
  private static final String STAGE_DIR_NAME = "stage";
  private static final String ZERO_QUOTA_APP_ID = "zero-quota-app";
  private static final String ABSENT_QUOTA_APP_ID = "absent-quota-app";
  private static final String MANIFEST_FILE_NAME = "cryptad-app.properties";
  private static final String MKFIFO_COMMAND = "mkfifo";
  private static final String NETWORK_ACCESS_PERMISSION = "network.access";
  private static final String FILE_READ_PERMISSION = "file.read";
  private static final List<String> STANDARD_PERMISSIONS =
      List.of(NETWORK_ACCESS_PERMISSION, FILE_READ_PERMISSION);
  private static final String STANDARD_PERMISSIONS_TEXT =
      NETWORK_ACCESS_PERMISSION + "," + FILE_READ_PERMISSION;
  private static final long POLL_INTERVAL_NANOS = Duration.ofMillis(10).toNanos();
  private static final LocalProcessAppHost.TimingConfig TEST_TIMING =
      new LocalProcessAppHost.TimingConfig(
          Duration.ofMillis(300),
          Duration.ofMillis(80),
          Duration.ofMillis(40),
          Duration.ofMillis(40),
          Duration.ofMillis(20),
          Duration.ofMillis(1),
          Duration.ofMillis(2),
          Duration.ofMillis(20));
  private static final Duration TEST_LOOP_SLEEP = Duration.ofMillis(50);
  private static final Duration TEST_DELAYED_WRAPPER_EXIT = Duration.ofMillis(120);
  private static final Duration TEST_POST_CAPTURE_DELAY =
      TEST_TIMING.startupProcessCaptureWindow().plusMillis(10);
  private static final Duration TEST_LATE_CHILD_DELAY =
      TEST_TIMING.startupExitGracePeriod().plusMillis(25);
  private static final Duration TEST_POST_SPAWN_EXIT_DELAY = Duration.ofMillis(40);
  private static final Duration TEST_SHORT_EXIT_DELAY = Duration.ofMillis(50);
  private static final Duration TEST_CLEAN_CHILD_EXIT_DELAY = Duration.ofMillis(500);
  private static final String TEST_LOOP_SLEEP_SECONDS = secondsLiteral(TEST_LOOP_SLEEP);
  private static final String TEST_DELAYED_WRAPPER_EXIT_SECONDS =
      secondsLiteral(TEST_DELAYED_WRAPPER_EXIT);
  private static final String TEST_POST_CAPTURE_DELAY_SECONDS =
      secondsLiteral(TEST_POST_CAPTURE_DELAY);
  private static final String TEST_LATE_CHILD_DELAY_SECONDS = secondsLiteral(TEST_LATE_CHILD_DELAY);
  private static final String TEST_POST_SPAWN_EXIT_DELAY_SECONDS =
      secondsLiteral(TEST_POST_SPAWN_EXIT_DELAY);
  private static final String TEST_SHORT_EXIT_DELAY_SECONDS = secondsLiteral(TEST_SHORT_EXIT_DELAY);
  private static final String TEST_CLEAN_CHILD_EXIT_DELAY_SECONDS =
      secondsLiteral(TEST_CLEAN_CHILD_EXIT_DELAY);
  private static final String LATE_CHILD_APP_ID = "late-child-app";
  private static final String SHELL_NOEXEC_APP_ID = "shell-noexec-app";
  private static final String WRAPPER_SCRIPT =
      """
      #!/bin/sh
      set -eu
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      wait "$child"
      """
          .formatted(CHILD_SCRIPT_PATH, CHILD_PID_FILE_NAME);
  private static final String CHILD_PROCESS_SCRIPT =
      """
      #!/bin/sh
      trap '' TERM INT
      while :; do
        sleep %s
      done
      """
          .formatted(TEST_LOOP_SLEEP_SECONDS);
  private static final String DAEMONIZED_CHILD_PROCESS_SCRIPT =
      """
      #!/bin/sh
      trap 'exit 0' TERM INT
      while :; do
        sleep %s
      done
      """
          .formatted(TEST_LOOP_SLEEP_SECONDS);
  private static final String DETACHED_CHILD_PROCESS_SCRIPT =
      """
      #!/bin/sh
      trap '' HUP
      trap 'exit 0' TERM INT
      while :; do
        sleep %s
      done
      """
          .formatted(TEST_LOOP_SLEEP_SECONDS);
  private static final String DAEMONIZING_WRAPPER_IMMEDIATE_EXIT_SCRIPT =
      """
      #!/bin/sh
      set -eu
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      exit 0
      """
          .formatted(CHILD_SCRIPT_PATH, CHILD_PID_FILE_NAME);
  private static final String DAEMONIZING_WRAPPER_DELAYED_EXIT_SCRIPT =
      """
      #!/bin/sh
      set -eu
      echo "$$" > "$CRYPTAD_APP_RUN_DIR/wrapper.pid"
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      sleep %s
      echo exited > "$CRYPTAD_APP_RUN_DIR/wrapper-exited.txt"
      exit 0
      """
          .formatted(CHILD_SCRIPT_PATH, CHILD_PID_FILE_NAME, TEST_DELAYED_WRAPPER_EXIT_SECONDS);
  private static final String DAEMONIZING_WRAPPER_POST_CAPTURE_EXIT_SCRIPT =
      """
      #!/bin/sh
      set -eu
      sleep %s
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      exit 0
      """
          .formatted(TEST_POST_CAPTURE_DELAY_SECONDS, CHILD_SCRIPT_PATH, CHILD_PID_FILE_NAME);
  private static final String DAEMONIZING_WRAPPER_VIA_HELPER_SCRIPT =
      """
      #!/bin/sh
      set -eu
      ./bin/helper.sh &
      exit 0
      """;
  private static final String DELAYED_DAEMONIZING_HELPER_SCRIPT =
      """
      #!/bin/sh
      set -eu
      sleep %s
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      exit 0
      """
          .formatted(TEST_POST_CAPTURE_DELAY_SECONDS, CHILD_SCRIPT_PATH, CHILD_PID_FILE_NAME);
  private static final String POST_CAPTURE_PYTHON_DAEMONIZER =
      """
      #!/usr/bin/env %s
      import os
      import pathlib
      import subprocess
      import time

      time.sleep(%s)
      child = subprocess.Popen(["./%s"])
      pathlib.Path(os.environ["CRYPTAD_APP_RUN_DIR"], "%s").write_text(
          f"{child.pid}\\n", encoding="utf-8")
      """
          .formatted(
              PYTHON3_COMMAND,
              TEST_POST_CAPTURE_DELAY_SECONDS,
              CHILD_SCRIPT_PATH,
              CHILD_PID_FILE_NAME);
  private static final String LATE_CHILD_DIRECT_EXECUTABLE =
      """
      #!/bin/sh
      set -eu
      sleep %s
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      sleep %s
      echo exited > "$CRYPTAD_APP_RUN_DIR/wrapper-exited.txt"
      exit 0
      """
          .formatted(
              TEST_LATE_CHILD_DELAY_SECONDS,
              CHILD_SCRIPT_PATH,
              CHILD_PID_FILE_NAME,
              TEST_POST_SPAWN_EXIT_DELAY_SECONDS);
  private static final String STDIN_EOF_SCRIPT =
      """
      #!/bin/sh
      set -eu
      cat >/dev/null
      echo closed > "$CRYPTAD_APP_RUN_DIR/stdin-closed.txt"
      while :; do
        sleep %s
      done
      """
          .formatted(TEST_LOOP_SLEEP_SECONDS);
  private static final String SINGLE_RUN_EXIT_SCRIPT =
      """
      #!/bin/sh
      set -eu
      count_file="$CRYPTAD_APP_RUN_DIR/run-count.txt"
      count=1
      if [ -f "$count_file" ]; then
        count=$(( $(cat "$count_file") + 1 ))
      fi
      printf '%s\\n' "$count" > "$count_file"
      exit 0
      """;
  private static final String DELAYED_STARTUP_EXIT_SCRIPT =
      """
      #!/bin/sh
      set -eu
      sleep %s
      exit 0
      """
          .formatted(TEST_SHORT_EXIT_DELAY_SECONDS);
  private static final String WORKING_DIRECTORY_AND_TOKEN_LOG_SCRIPT =
      """
      #!/bin/sh
      set -eu
      pwd > "$CRYPTAD_APP_RUN_DIR/cwd.txt"
      echo "cwd=$(pwd)"
      echo "CRYPTAD_APP_DATA_DIR=$CRYPTAD_APP_DATA_DIR"
      echo "CRYPTAD_APP_CACHE_DIR=$CRYPTAD_APP_CACHE_DIR"
      echo "CRYPTAD_APP_RUN_DIR=$CRYPTAD_APP_RUN_DIR"
      echo "process-log=$CRYPTAD_APP_RUN_DIR/%s"
      echo "CRYPTAD_APP_TOKEN=$CRYPTAD_APP_TOKEN"
      echo "raw-token=$CRYPTAD_APP_TOKEN"
      while :; do
        sleep %s
      done
      """
          .formatted(PROCESS_LOG_FILE_NAME, TEST_LOOP_SLEEP_SECONDS);
  private static final String IMMEDIATE_TOKEN_CRASH_SCRIPT =
      """
      #!/bin/sh
      set -eu
      echo "raw-token=$CRYPTAD_APP_TOKEN"
      exit 7
      """;
  private static final String IMMEDIATE_CRASH_SCRIPT =
      """
      #!/bin/sh
      exit 7
      """;
  private static final String RESTART_ON_FAILURE_SCRIPT =
      """
      #!/bin/sh
      set -eu
      count_file="$CRYPTAD_APP_RUN_DIR/restart-count.txt"
      count=0
      if [ -f "$count_file" ]; then
        count="$(cat "$count_file")"
      fi
      count=$((count + 1))
      printf '%%s\\n' "$count" > "$count_file"
      if [ "$count" -eq 1 ]; then
        sleep 0.500
        exit 7
      fi
      trap 'exit 0' TERM INT
      while :; do
        sleep %s
      done
      """
          .formatted(TEST_LOOP_SLEEP_SECONDS);
  private static final String RESTART_STORM_SCRIPT =
      """
      #!/bin/sh
      set -eu
      count_file="$CRYPTAD_APP_RUN_DIR/restart-storm-count.txt"
      count=0
      if [ -f "$count_file" ]; then
        count="$(cat "$count_file")"
      fi
      count=$((count + 1))
      printf '%s\\n' "$count" > "$count_file"
      sleep 0.500
      exit 7
      """;
  private static final String WAITING_WRAPPER_CLEAN_EXIT_SCRIPT =
      """
      #!/bin/sh
      set -eu
      count_file="$CRYPTAD_APP_RUN_DIR/wait-wrapper-run-count.txt"
      count=0
      if [ -f "$count_file" ]; then
        count="$(cat "$count_file")"
      fi
      count=$((count + 1))
      printf '%%s\\n' "$count" > "$count_file"
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      wait "$child"
      """
          .formatted(CHILD_SCRIPT_PATH, CHILD_PID_FILE_NAME);
  private static final String CLEAN_EXIT_CHILD_SCRIPT =
      """
      #!/bin/sh
      set -eu
      sleep %s
      exit 0
      """
          .formatted(TEST_CLEAN_CHILD_EXIT_DELAY_SECONDS);
  private static final String RESTART_ATTEMPT_STARTUP_FAILURE_SCRIPT =
      """
      #!/bin/sh
      set -eu
      count_file="$CRYPTAD_APP_RUN_DIR/restart-startup-failure-count.txt"
      count=0
      if [ -f "$count_file" ]; then
        count="$(cat "$count_file")"
      fi
      count=$((count + 1))
      printf '%s\\n' "$count" > "$count_file"
      if [ "$count" -eq 1 ]; then
        sleep 0.500
        exit 7
      fi
      exit 9
      """;
  private static final String DAEMONIZED_RESTART_ON_FAILURE_CHILD_SCRIPT =
      """
      #!/bin/sh
      set -eu
      trap '' HUP
      count_file="$CRYPTAD_APP_RUN_DIR/daemonized-restart-count.txt"
      count=0
      if [ -f "$count_file" ]; then
        count="$(cat "$count_file")"
      fi
      count=$((count + 1))
      printf '%%s\\n' "$count" > "$count_file"
      if [ "$count" -eq 1 ]; then
        sleep 0.500
        exit 7
      fi
      trap 'exit 0' TERM INT
      while :; do
        sleep %s
      done
      """
          .formatted(TEST_LOOP_SLEEP_SECONDS);
  private static final String RESTART_STOP_SUPPRESSION_SCRIPT =
      """
      #!/bin/sh
      set -eu
      count_file="$CRYPTAD_APP_RUN_DIR/restart-count.txt"
      count=0
      if [ -f "$count_file" ]; then
        count="$(cat "$count_file")"
      fi
      count=$((count + 1))
      printf '%%s\\n' "$count" > "$count_file"
      trap 'exit 7' TERM INT
      while :; do
        sleep %s
      done
      """
          .formatted(TEST_LOOP_SLEEP_SECONDS);

  @TempDir private Path tempDir;

  @Test
  void installFromDirectory_whenUsingProductionDefault_expectRejectsUnsignedBundle()
      throws IOException {
    AppHost host = new LocalProcessAppHost(layout());
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);

    AppBundleVerificationException exception =
        assertThrows(
            AppBundleVerificationException.class, () -> host.installFromDirectory(stagedApp));

    assertEquals(SIGNED_BUNDLE_REQUIRED_MESSAGE, exception.getMessage());
    assertTrue(host.describe(SAMPLE_APP_ID).isEmpty());
    assertEquals(List.of(), host.listInstalled());
  }

  @Test
  void installFromDirectory_whenVerifierRejectsCopiedBundle_expectVerifierRunsBeforeManifestRead()
      throws IOException {
    AtomicReference<Path> verifiedBundle = new AtomicReference<>();
    AppHost host =
        requireSignedHost(
            copiedBundleDirectory -> {
              verifiedBundle.set(copiedBundleDirectory);
              throw new AppBundleVerificationException(SIGNED_BUNDLE_REQUIRED_MESSAGE);
            });
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    Files.writeString(stagedApp.resolve(MANIFEST_FILE_NAME), "manifest.version=1\n");

    AppBundleVerificationException exception =
        assertThrows(
            AppBundleVerificationException.class, () -> host.installFromDirectory(stagedApp));

    Path copiedBundle = verifiedBundle.get();
    assertEquals(SIGNED_BUNDLE_REQUIRED_MESSAGE, exception.getMessage());
    assertNotNull(copiedBundle);
    assertNotEquals(stagedApp.toAbsolutePath().normalize(), copiedBundle);
    assertTrue(copiedBundle.startsWith(layout().installedAppsDir()));
    assertTrue(copiedBundle.getFileName().toString().startsWith("app-install-"));
  }

  @SuppressWarnings("unused")
  @Test
  void installFromDirectory_whenVerifierThrowsManagedTreeIoFailure_expectRawIoFailure()
      throws IOException {
    IOException managedTreeFailure = new IOException("managed copied bundle became unreadable");
    AppHost host =
        requireSignedHost(
            copiedBundleDirectory -> {
              throw managedTreeFailure;
            });
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);

    IOException exception =
        assertThrows(IOException.class, () -> host.installFromDirectory(stagedApp));

    assertSame(managedTreeFailure, exception);
  }

  @Test
  void installFromDirectory_whenInstallingValidBundle_expectCopiedLayoutAndDescribe()
      throws IOException {
    KeyPair keyPair = generateEd25519KeyPair();
    AppHost host = signedHost(keyPair);
    Path stagedApp = signBundle(stageInstalledApp(SAMPLE_APP_ID), keyPair);

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    assertEquals(SAMPLE_APP_ID, installation.appId());
    assertEquals(4096L, installation.manifest().dataQuotaBytes());
    assertEquals(1024L, installation.manifest().cacheQuotaBytes());
    assertTrue(Files.isRegularFile(installation.paths().manifestFile()));
    assertTrue(
        Files.isRegularFile(
            installation.paths().resolveInstalledPath(installation.manifest().execPath())));
    assertTrue(Files.isDirectory(installation.paths().dataDir()));
    assertTrue(Files.isDirectory(installation.paths().cacheDir()));
    assertTrue(Files.isDirectory(installation.paths().runDir()));
    assertEquals(java.util.List.of(installation), host.listInstalled());
    assertEquals(installation.manifest(), host.describe(SAMPLE_APP_ID).orElseThrow().manifest());
  }

  @Test
  void installFromDirectory_whenAppAlreadyInstalled_expectFailure() throws IOException {
    AppHost host = requireSignedHost(_ -> {});
    Path stagedApp = stageInstalledApp(DUPLICATE_APP_ID);

    host.installFromDirectory(stagedApp);

    assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));
  }

  @Test
  void
      updateFromDirectory_whenInstalledStoppedApp_expectManifestAndExecutableReplacedPreservingMutableDirs()
          throws IOException {
    KeyPair keyPair = generateEd25519KeyPair();
    AppHost host = signedHost(keyPair);
    Path installedStage =
        signBundle(
            stageInstalledAppAt(
                tempDir.resolve("stage-installed").resolve(SAMPLE_APP_ID),
                SAMPLE_APP_ID,
                APP_VERSION,
                """
                #!/bin/sh
                printf 'old\\n'
                """,
                Map.of("bundle-only.txt", "old-bundle\n")),
            keyPair);
    InstalledAppSnapshot installation = host.installFromDirectory(installedStage);
    Path dataSentinel =
        Files.writeString(
            installation.paths().dataDir().resolve("preserve-data.txt"),
            PRESERVED_DATA_CONTENT,
            StandardCharsets.UTF_8);
    Path cacheSentinel =
        Files.writeString(
            installation.paths().cacheDir().resolve("preserve-cache.txt"),
            PRESERVED_CACHE_CONTENT,
            StandardCharsets.UTF_8);
    Path runSentinel =
        Files.writeString(
            installation.paths().runDir().resolve("preserve-run.txt"),
            PRESERVED_RUN_CONTENT,
            StandardCharsets.UTF_8);
    Path updatedStage =
        signBundle(
            stageInstalledAppAt(
                tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve(SAMPLE_APP_ID),
                SAMPLE_APP_ID,
                UPDATED_APP_VERSION,
                UPDATED_BUNDLE_SCRIPT,
                Map.of(NEW_BUNDLE_FILE_NAME, NEW_BUNDLE_CONTENT)),
            keyPair);

    InstalledAppSnapshot updated = host.updateFromDirectory(SAMPLE_APP_ID, updatedStage);

    assertEquals(UPDATED_APP_VERSION, updated.manifest().appVersion());
    assertEquals(installation.paths(), updated.paths());
    assertEquals(PRESERVED_DATA_CONTENT, Files.readString(dataSentinel, StandardCharsets.UTF_8));
    assertEquals(PRESERVED_CACHE_CONTENT, Files.readString(cacheSentinel, StandardCharsets.UTF_8));
    assertEquals(PRESERVED_RUN_CONTENT, Files.readString(runSentinel, StandardCharsets.UTF_8));
    assertFalse(Files.exists(updated.paths().installedRoot().resolve("bundle-only.txt")));
    assertEquals(
        NEW_BUNDLE_CONTENT,
        Files.readString(
            updated.paths().installedRoot().resolve(NEW_BUNDLE_FILE_NAME), StandardCharsets.UTF_8));
    assertEquals(
        UPDATED_BUNDLE_SCRIPT,
        Files.readString(
            updated.paths().executablePath(updated.manifest()), StandardCharsets.UTF_8));
    assertEquals(
        UPDATED_APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertEquals(List.of(updated), host.listInstalled());
  }

  @Test
  void installFromDirectory_whenNewInstallCompletes_expectNoRollbackRecord() throws IOException {
    AppHost host = allowUnsignedHost();

    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));

    assertTrue(host.rollbackStatus(SAMPLE_APP_ID).isEmpty());
  }

  @Test
  void updateFromDirectory_whenUpdatedTwice_expectOnlyImmediatelyPreviousBundleRetained()
      throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(
        stageInstalledAppAt(
            tempDir.resolve("stage-retention-install").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of("v2-marker.txt", "version-2\n")));
    host.updateFromDirectory(
        SAMPLE_APP_ID,
        stageInstalledAppAt(
            tempDir.resolve("stage-retention-first-update").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of("v3-marker.txt", "version-3\n")));

    AppRollbackRecord firstRollback = host.rollbackStatus(SAMPLE_APP_ID).orElseThrow();
    assertEquals(APP_VERSION, firstRollback.appVersion());

    host.updateFromDirectory(
        SAMPLE_APP_ID,
        stageInstalledAppAt(
            tempDir.resolve("stage-retention-second-update").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            SECOND_UPDATED_APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of("v4-marker.txt", "version-4\n")));

    AppRollbackRecord retainedRollback = host.rollbackStatus(SAMPLE_APP_ID).orElseThrow();
    assertEquals(UPDATED_APP_VERSION, retainedRollback.appVersion());

    InstalledAppSnapshot rolledBack = host.rollback(SAMPLE_APP_ID);

    assertEquals(UPDATED_APP_VERSION, rolledBack.manifest().appVersion());
    assertTrue(Files.exists(rolledBack.paths().installedRoot().resolve("v3-marker.txt")));
    assertFalse(Files.exists(rolledBack.paths().installedRoot().resolve("v2-marker.txt")));
  }

  @Test
  void rollback_whenPreviousBundleExists_expectRestoresBundleAndPreservesMutableDirs()
      throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation =
        host.installFromDirectory(
            stageInstalledAppAt(
                tempDir.resolve("stage-rollback-install").resolve(SAMPLE_APP_ID),
                SAMPLE_APP_ID,
                APP_VERSION,
                """
                #!/bin/sh
                printf 'old\\n'
                """,
                Map.of("old-bundle.txt", "old-bundle\n")));
    Path updatedStage =
        stageInstalledAppAt(
            tempDir.resolve("stage-rollback-update").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            UPDATED_BUNDLE_SCRIPT,
            Map.of(NEW_BUNDLE_FILE_NAME, NEW_BUNDLE_CONTENT));
    host.updateFromDirectory(SAMPLE_APP_ID, updatedStage);
    Path dataSentinel =
        Files.writeString(
            installation.paths().dataDir().resolve("rollback-data.txt"),
            PRESERVED_DATA_CONTENT,
            StandardCharsets.UTF_8);
    Path cacheSentinel =
        Files.writeString(
            installation.paths().cacheDir().resolve("rollback-cache.txt"),
            PRESERVED_CACHE_CONTENT,
            StandardCharsets.UTF_8);
    Path runSentinel =
        Files.writeString(
            installation.paths().runDir().resolve("rollback-run.txt"),
            PRESERVED_RUN_CONTENT,
            StandardCharsets.UTF_8);

    InstalledAppSnapshot rolledBack = host.rollback(SAMPLE_APP_ID);

    assertEquals(APP_VERSION, rolledBack.manifest().appVersion());
    assertTrue(Files.exists(rolledBack.paths().installedRoot().resolve("old-bundle.txt")));
    assertFalse(Files.exists(rolledBack.paths().installedRoot().resolve(NEW_BUNDLE_FILE_NAME)));
    assertEquals(PRESERVED_DATA_CONTENT, Files.readString(dataSentinel, StandardCharsets.UTF_8));
    assertEquals(PRESERVED_CACHE_CONTENT, Files.readString(cacheSentinel, StandardCharsets.UTF_8));
    assertEquals(PRESERVED_RUN_CONTENT, Files.readString(runSentinel, StandardCharsets.UTF_8));
    assertEquals(
        UPDATED_APP_VERSION, host.rollbackStatus(SAMPLE_APP_ID).orElseThrow().appVersion());
  }

  @Test
  void rollback_whenPurposeSpecificVerifiersConfigured_expectHistoricalVerifierUsed()
      throws IOException {
    AtomicInteger newBundleVerifications = new AtomicInteger();
    AtomicInteger historicalVerifications = new AtomicInteger();
    AppInstallVerificationPolicy verificationPolicy =
        AppInstallVerificationPolicy.requireSigned(
            _ -> newBundleVerifications.incrementAndGet(),
            _ -> historicalVerifications.incrementAndGet());
    LocalProcessAppHost host =
        new LocalProcessAppHost(
            layout(),
            Duration.ofSeconds(1),
            new java.security.SecureRandom(),
            new AppEnv(),
            TEST_TIMING,
            verificationPolicy);
    host.installFromDirectory(
        stageInstalledAppAt(
            tempDir.resolve("stage-purpose-install").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of()));
    host.updateFromDirectory(
        SAMPLE_APP_ID,
        stageInstalledAppAt(
            tempDir.resolve("stage-purpose-update").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of()));

    InstalledAppSnapshot rolledBack = host.rollback(SAMPLE_APP_ID);

    assertEquals(APP_VERSION, rolledBack.manifest().appVersion());
    assertEquals(2, newBundleVerifications.get());
    assertEquals(1, historicalVerifications.get());
  }

  @Test
  void start_whenPurposeSpecificVerifiersConfigured_expectEveryLaunchUsesHistoricalVerifier()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AtomicInteger newBundleVerifications = new AtomicInteger();
    AtomicInteger historicalVerifications = new AtomicInteger();
    AppInstallVerificationPolicy verificationPolicy =
        AppInstallVerificationPolicy.requireSigned(
            _ -> newBundleVerifications.incrementAndGet(),
            _ -> historicalVerifications.incrementAndGet());
    LocalProcessAppHost host =
        new LocalProcessAppHost(
            layout(),
            Duration.ofSeconds(1),
            new java.security.SecureRandom(),
            appEnv,
            TEST_TIMING,
            verificationPolicy);
    host.installFromDirectory(stageInstalledRunnerApp(DAEMONIZED_CHILD_PROCESS_SCRIPT));

    host.start(RUNNER_APP_ID);
    assertTrue(host.stop(RUNNER_APP_ID));
    host.start(RUNNER_APP_ID);

    try {
      assertEquals(1, newBundleVerifications.get());
      assertEquals(2, historicalVerifications.get());
    } finally {
      host.stop(RUNNER_APP_ID);
    }
  }

  @Test
  void start_whenHistoricalVerifierRejectsInstalledBundle_expectLaunchRejectedBeforeSideEffects()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AtomicReference<Path> verifiedRoot = new AtomicReference<>();
    AppInstallVerificationPolicy verificationPolicy =
        AppInstallVerificationPolicy.requireSigned(
            _ -> {},
            installedRoot -> {
              verifiedRoot.set(installedRoot);
              throw new AppBundleVerificationException(
                  "installed app signing key is no longer historically trusted");
            });
    LocalProcessAppHost host =
        new LocalProcessAppHost(
            layout(),
            Duration.ofSeconds(1),
            new java.security.SecureRandom(),
            appEnv,
            TEST_TIMING,
            verificationPolicy);
    InstalledAppSnapshot installation =
        host.installFromDirectory(stageInstalledRunnerApp(DAEMONIZED_CHILD_PROCESS_SCRIPT));

    AppBundleVerificationException exception =
        assertThrows(AppBundleVerificationException.class, () -> host.start(RUNNER_APP_ID));

    assertEquals(
        "installed app signing key is no longer historically trusted", exception.getMessage());
    assertEquals(installation.paths().installedRoot(), verifiedRoot.get());
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertFalse(Files.exists(installation.paths().processLogFile()));
  }

  @Test
  void rollback_whenAppIsRunning_expectFailureAndInstalledBundleUnchanged() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledRunnerApp(DAEMONIZED_CHILD_PROCESS_SCRIPT));
    host.updateFromDirectory(
        RUNNER_APP_ID,
        stageInstalledAppAt(
            tempDir.resolve("stage-running-rollback-update").resolve(RUNNER_APP_ID),
            RUNNER_APP_ID,
            UPDATED_APP_VERSION,
            DAEMONIZED_CHILD_PROCESS_SCRIPT,
            Map.of()));
    host.start(RUNNER_APP_ID);

    try {
      AppHostException exception =
          assertThrows(AppHostException.class, () -> host.rollback(RUNNER_APP_ID));

      assertEquals("cannot rollback a running app: " + RUNNER_APP_ID, exception.getMessage());
      assertEquals(
          UPDATED_APP_VERSION, host.describe(RUNNER_APP_ID).orElseThrow().manifest().appVersion());
    } finally {
      host.stop(RUNNER_APP_ID);
    }
  }

  @Test
  void uninstall_whenRollbackRecordExists_expectRollbackRecordCleared() throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    host.updateFromDirectory(
        SAMPLE_APP_ID,
        stageInstalledAppAt(
            tempDir.resolve("stage-uninstall-rollback-update").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of()));
    assertTrue(host.rollbackStatus(SAMPLE_APP_ID).isPresent());

    host.uninstall(SAMPLE_APP_ID);

    assertTrue(host.rollbackStatus(SAMPLE_APP_ID).isEmpty());
  }

  @Test
  void uninstall_whenPreserveDataRequested_expectDataDirectoryKeptOnly() throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Path dataSentinel =
        Files.writeString(
            installation.paths().dataDir().resolve("durable-state.txt"),
            PRESERVED_DATA_CONTENT,
            StandardCharsets.UTF_8);
    Files.writeString(
        installation.paths().cacheDir().resolve("cache-state.txt"),
        "remove-cache",
        StandardCharsets.UTF_8);
    Files.writeString(
        installation.paths().runDir().resolve("run-state.txt"),
        "remove-run",
        StandardCharsets.UTF_8);

    host.uninstall(SAMPLE_APP_ID, AppUninstallOptions.preservingData());

    assertFalse(Files.exists(installation.paths().installedRoot()));
    assertTrue(Files.isDirectory(installation.paths().dataDir()));
    assertEquals(PRESERVED_DATA_CONTENT, Files.readString(dataSentinel, StandardCharsets.UTF_8));
    assertFalse(Files.exists(installation.paths().cacheDir()));
    assertFalse(Files.exists(installation.paths().runDir()));
    assertTrue(host.describe(SAMPLE_APP_ID).isEmpty());
  }

  @Test
  void updateFromDirectory_whenUpdateFails_expectCurrentBundleAndRollbackRecordPreserved()
      throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    InstalledAppSnapshot updated =
        host.updateFromDirectory(
            SAMPLE_APP_ID,
            stageInstalledAppAt(
                tempDir.resolve("stage-failed-update-current").resolve(SAMPLE_APP_ID),
                SAMPLE_APP_ID,
                UPDATED_APP_VERSION,
                scriptContent(new AppEnv()),
                Map.of(NEW_BUNDLE_FILE_NAME, NEW_BUNDLE_CONTENT)));
    Path mismatchedStage =
        stageInstalledAppAt(
            tempDir.resolve("stage-failed-update-mismatch").resolve(DUPLICATE_APP_ID),
            DUPLICATE_APP_ID,
            SECOND_UPDATED_APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of("mismatched.txt", "mismatched\n"));

    assertThrows(
        AppManifestException.class, () -> host.updateFromDirectory(SAMPLE_APP_ID, mismatchedStage));

    assertEquals(
        UPDATED_APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertEquals(APP_VERSION, host.rollbackStatus(SAMPLE_APP_ID).orElseThrow().appVersion());
    assertEquals(
        NEW_BUNDLE_CONTENT,
        Files.readString(
            updated.paths().installedRoot().resolve(NEW_BUNDLE_FILE_NAME), StandardCharsets.UTF_8));
  }

  @Test
  void rollbackStatus_whenRecordExists_expectMetadataOmitsTokensAndHostPaths() throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);
    String launchToken = running.token();
    assertTrue(host.stop(RUNNER_APP_ID));
    host.updateFromDirectory(
        RUNNER_APP_ID,
        stageInstalledAppAt(
            tempDir.resolve("stage-metadata-rollback-update").resolve(RUNNER_APP_ID),
            RUNNER_APP_ID,
            UPDATED_APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of()));

    AppRollbackRecord rollbackRecord = host.rollbackStatus(RUNNER_APP_ID).orElseThrow();
    String recordText = rollbackRecord.toString();

    assertEquals(RUNNER_APP_ID, rollbackRecord.appId());
    assertEquals(APP_VERSION, rollbackRecord.appVersion());
    assertFalse(recordText.contains(launchToken));
    assertFalse(recordText.contains(tempDir.toString()));
    assertFalse(recordText.contains(installation.paths().installedRoot().toString()));
    assertFalse(recordText.contains(installation.paths().dataDir().toString()));
    assertFalse(recordText.contains(installation.paths().cacheDir().toString()));
    assertFalse(recordText.contains(installation.paths().runDir().toString()));
  }

  @Test
  void rollbackStatus_whenRollbackManifestTargetsDifferentApp_expectInvalidRecordRejected()
      throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    host.updateFromDirectory(
        SAMPLE_APP_ID,
        stageInstalledAppAt(
            tempDir.resolve("stage-wrong-rollback-update").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of()));
    Path rollbackManifest =
        layout().rollbackAppsDir().resolve(SAMPLE_APP_ID).resolve(MANIFEST_FILE_NAME);
    Files.writeString(
        rollbackManifest,
        Files.readString(rollbackManifest, StandardCharsets.UTF_8)
            .replace("app.id=" + SAMPLE_APP_ID, "app.id=" + DUPLICATE_APP_ID),
        StandardCharsets.UTF_8);

    AppManifestException exception =
        assertThrows(AppManifestException.class, () -> host.rollbackStatus(SAMPLE_APP_ID));

    assertEquals(
        "installed manifest app.id does not match directory name: " + SAMPLE_APP_ID,
        exception.getMessage());
  }

  @Test
  void installFromDirectory_whenSignedBundleIsTampered_expectVerificationFailure()
      throws Exception {
    KeyPair keyPair = generateEd25519KeyPair();
    AppHost host = signedHost(keyPair);
    Path stagedApp = signBundle(stageInstalledApp(SAMPLE_APP_ID), keyPair);
    Files.writeString(stagedApp.resolve(CONTENT_FILE_NAME), "tampered", StandardCharsets.UTF_8);

    AppBundleVerificationException exception =
        assertThrows(
            AppBundleVerificationException.class, () -> host.installFromDirectory(stagedApp));

    assertEquals("digest sidecar does not match bundle contents", exception.getMessage());
  }

  @Test
  void
      installFromDirectory_whenDevelopmentPolicyReceivesSignatureSidecars_expectVerificationFailure()
          throws Exception {
    AppHost host = allowUnsignedHost();
    KeyPair keyPair = generateEd25519KeyPair();
    Path stagedApp = signBundle(stageInstalledApp(SAMPLE_APP_ID), keyPair);

    AppBundleVerificationException exception =
        assertThrows(
            AppBundleVerificationException.class, () -> host.installFromDirectory(stagedApp));

    assertEquals("unknown trusted key id: " + TEST_KEY_ID, exception.getMessage());
  }

  @Test
  void updateFromDirectory_whenVerifierRejectsCopiedBundle_expectVerifierRunsBeforeManifestRead()
      throws IOException {
    allowUnsignedHost().installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    AtomicReference<Path> verifiedBundle = new AtomicReference<>();
    AppHost host =
        requireSignedHost(
            copiedBundleDirectory -> {
              verifiedBundle.set(copiedBundleDirectory);
              throw new AppBundleVerificationException(SIGNED_BUNDLE_REQUIRED_MESSAGE);
            });
    Path updatedStage =
        stageInstalledAppAt(
            tempDir.resolve("stage-update-unsigned").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of());
    Files.writeString(updatedStage.resolve(MANIFEST_FILE_NAME), "manifest.version=1\n");

    AppBundleVerificationException exception =
        assertThrows(
            AppBundleVerificationException.class,
            () -> host.updateFromDirectory(SAMPLE_APP_ID, updatedStage));

    Path copiedBundle = verifiedBundle.get();
    assertEquals(SIGNED_BUNDLE_REQUIRED_MESSAGE, exception.getMessage());
    assertNotNull(copiedBundle);
    assertNotEquals(updatedStage.toAbsolutePath().normalize(), copiedBundle);
    assertTrue(copiedBundle.startsWith(layout().installedAppsDir()));
    assertTrue(copiedBundle.getFileName().toString().startsWith("app-install-"));
    assertEquals(APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
  }

  @Test
  void updateFromDirectory_whenInstalledManifestMissing_expectBundleRepaired() throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Files.delete(installation.paths().manifestFile());
    Path updatedStage =
        stageInstalledAppAt(
            tempDir.resolve("stage-repair").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            """
            #!/bin/sh
            printf 'repaired\\n'
            """,
            Map.of("repair-bundle.txt", "repair-bundle\n"));

    InstalledAppSnapshot updated = host.updateFromDirectory(SAMPLE_APP_ID, updatedStage);

    assertEquals(UPDATED_APP_VERSION, updated.manifest().appVersion());
    assertEquals(
        UPDATED_APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertEquals(
        "repair-bundle\n",
        Files.readString(
            updated.paths().installedRoot().resolve("repair-bundle.txt"), StandardCharsets.UTF_8));
  }

  @Test
  void updateFromDirectory_whenStagedManifestTargetsDifferentApp_expectFailure()
      throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Path mismatchedStage =
        stageInstalledAppAt(
            tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve(DUPLICATE_APP_ID),
            DUPLICATE_APP_ID,
            UPDATED_APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of());

    AppManifestException exception =
        assertThrows(
            AppManifestException.class,
            () -> host.updateFromDirectory(SAMPLE_APP_ID, mismatchedStage));

    assertTrue(exception.getMessage().contains("does not match requested app.id"));
    assertEquals(APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
  }

  @Test
  void updateFromDirectory_whenAppNotInstalled_expectFailure() throws IOException {
    AppHostLayout appHostLayout = layout();
    AppHost host = developmentHost(appHostLayout);
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    Path transactionRoot = Files.createDirectories(appHostLayout.appMutationTransactionsDir());

    try (WatchService watchService = watchForCreatedEntries(transactionRoot)) {
      AppHostException exception =
          assertThrows(
              AppHostException.class, () -> host.updateFromDirectory(SAMPLE_APP_ID, stagedApp));

      assertEquals("app is not installed: " + SAMPLE_APP_ID, exception.getMessage());
      assertNoCreatedEntry(watchService, transactionRoot);
    }
  }

  @Test
  void updateFromDirectory_whenInstalledManifestUnreadable_expectReplacementRepairsBundle()
      throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Files.delete(installation.paths().manifestFile());
    Path updatedStage =
        stageInstalledAppAt(
            tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of(NEW_BUNDLE_FILE_NAME, NEW_BUNDLE_CONTENT));

    assertThrows(IOException.class, () -> host.describe(SAMPLE_APP_ID));

    InstalledAppSnapshot updated = host.updateFromDirectory(SAMPLE_APP_ID, updatedStage);

    assertEquals(UPDATED_APP_VERSION, updated.manifest().appVersion());
    assertEquals(
        UPDATED_APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertEquals(
        NEW_BUNDLE_CONTENT,
        Files.readString(
            updated.paths().installedRoot().resolve(NEW_BUNDLE_FILE_NAME), StandardCharsets.UTF_8));
  }

  @Test
  void updateFromDirectory_whenReplacingStoppedApp_expectPreviousBundleRecordedForRollback()
      throws IOException {
    AtomicInteger cleanupAttempts = new AtomicInteger();
    LocalProcessAppHost host =
        allowUnsignedHost(
            Duration.ofSeconds(1),
            new AppEnv(),
            root -> {
              if (root.getFileName().toString().startsWith("app-rollback-backup-")) {
                cleanupAttempts.incrementAndGet();
                throw new IOException("simulated backup cleanup failure");
              }
              deleteTestTree(root);
            });
    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Path firstUpdatedStage =
        stageInstalledAppAt(
            tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve("first").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            scriptContent(new AppEnv()),
            Map.of(NEW_BUNDLE_FILE_NAME, NEW_BUNDLE_CONTENT));
    InstalledAppSnapshot firstUpdate = host.updateFromDirectory(SAMPLE_APP_ID, firstUpdatedStage);
    assertEquals(APP_VERSION, host.rollbackStatus(SAMPLE_APP_ID).orElseThrow().appVersion());
    assertEquals(0, cleanupAttempts.get());
    String secondUpdatedVersion = SECOND_UPDATED_APP_VERSION;
    Path secondUpdatedStage =
        stageInstalledAppAt(
            tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve("second").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            secondUpdatedVersion,
            scriptContent(new AppEnv()),
            Map.of(NEW_BUNDLE_FILE_NAME, "second-bundle\n"));

    InstalledAppSnapshot updated = host.updateFromDirectory(SAMPLE_APP_ID, secondUpdatedStage);

    assertEquals(secondUpdatedVersion, updated.manifest().appVersion());
    assertEquals(
        secondUpdatedVersion, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertEquals(
        firstUpdate.manifest().appVersion(),
        host.rollbackStatus(SAMPLE_APP_ID).orElseThrow().appVersion());
    assertEquals(1, cleanupAttempts.get());
    assertEquals(List.of(updated), host.listInstalled());
  }

  @Test
  void updateCatalogFromDirectory_whenOriginStoreIsUnsafe_expectBundleRemainsUnchanged()
      throws IOException {
    AppHostLayout layout = layout();
    LocalProcessAppHost host = developmentHost(layout);
    Path initial = stageInstalledApp(SAMPLE_APP_ID, EXIT_ZERO_SCRIPT, Map.of());
    InstalledAppOrigin initialOrigin = origin(APP_VERSION);
    host.installCatalogFromDirectory(initial, initialOrigin);
    Path originRoot = layout.appOriginProvenanceDir();
    Path savedOriginRoot = originRoot.resolveSibling("catalog-origin-saved");
    Files.move(originRoot, savedOriginRoot);
    Files.writeString(originRoot, "unsafe");
    Path update =
        stageInstalledAppAt(
            tempDir.resolve("catalog-update"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    InstalledAppOrigin updateOrigin = origin(UPDATED_APP_VERSION, initialOrigin.selfDigestSha256());

    assertThrows(
        IOException.class,
        () -> host.updateCatalogFromDirectory(SAMPLE_APP_ID, update, updateOrigin));

    assertEquals(APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
  }

  @Test
  void updateCatalogFromDirectory_whenStagedTargetIsInvalid_expectNoTransactionStarted()
      throws IOException {
    AppHostLayout appHostLayout = layout();
    LocalProcessAppHost host = developmentHost(appHostLayout);
    Path initial = stageInstalledApp(SAMPLE_APP_ID, EXIT_ZERO_SCRIPT, Map.of());
    InstalledAppOrigin initialOrigin = origin(APP_VERSION);
    host.installCatalogFromDirectory(initial, initialOrigin);
    Path mismatchedUpdate =
        stageInstalledAppAt(
            tempDir.resolve("mismatched-catalog-update"),
            DUPLICATE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    InstalledAppOrigin updateOrigin = origin(UPDATED_APP_VERSION, initialOrigin.selfDigestSha256());
    Path transactionRoot = Files.createDirectories(appHostLayout.appMutationTransactionsDir());

    try (WatchService watchService = watchForCreatedEntries(transactionRoot)) {
      assertThrows(
          AppManifestException.class,
          () -> host.updateCatalogFromDirectory(SAMPLE_APP_ID, mismatchedUpdate, updateOrigin));

      assertNoCreatedEntry(watchService, transactionRoot);
      assertEquals(APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
      assertEquals(initialOrigin, host.catalogOrigin(SAMPLE_APP_ID).orElseThrow());
    }
  }

  @Test
  void installCatalogFromDirectory_whenOriginNamesAnotherApp_expectNoBundleCommitted()
      throws IOException {
    LocalProcessAppHost host = developmentHost(layout());
    Path staged = stageInstalledApp(DUPLICATE_APP_ID);
    InstalledAppOrigin mismatchedOrigin = origin(APP_VERSION);

    assertThrows(
        AppHostException.class, () -> host.installCatalogFromDirectory(staged, mismatchedOrigin));

    assertTrue(host.describe(SAMPLE_APP_ID).isEmpty());
    assertTrue(host.describe(DUPLICATE_APP_ID).isEmpty());
    assertTrue(host.catalogOrigin(SAMPLE_APP_ID).isEmpty());
  }

  @Test
  void installCatalogFromDirectory_whenAuthorized_expectLeaseHeldThroughCommit()
      throws IOException {
    AppHostLayout layout = layout();
    LocalProcessAppHost host = developmentHost(layout);
    Path staged = stageInstalledApp(SAMPLE_APP_ID);
    InstalledAppOrigin origin = origin(APP_VERSION);
    AtomicBoolean authorized = new AtomicBoolean();
    AtomicBoolean committedBeforeLeaseClosed = new AtomicBoolean();

    InstalledAppSnapshot installed =
        host.installCatalogFromDirectory(
            staged,
            origin,
            targetOrigin -> {
              assertEquals(origin, targetOrigin);
              authorized.set(true);
              return () ->
                  committedBeforeLeaseClosed.set(
                      Files.isDirectory(layout.pathsFor(SAMPLE_APP_ID).installedRoot())
                          && Files.isRegularFile(
                              layout
                                  .appOriginProvenanceDir()
                                  .resolve(SAMPLE_APP_ID + ".properties")));
            });

    assertTrue(authorized.get());
    assertTrue(committedBeforeLeaseClosed.get());
    assertEquals(SAMPLE_APP_ID, installed.manifest().appId());
  }

  @Test
  void installCatalogFromDirectory_whenCopiedSignerDiffersFromOrigin_expectNoBundleCommitted()
      throws Exception {
    KeyPair approvedPublisher = generateEd25519KeyPair();
    KeyPair substitutedPublisher = generateEd25519KeyPair();
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(
                new TrustedAppKey(
                    APPROVED_PUBLISHER_KEY_ID,
                    AppBundleSignature.SIGNATURE_ALGORITHM,
                    approvedPublisher.getPublic()))
            .plus(
                TrustedAppKeys.of(
                    new TrustedAppKey(
                        SUBSTITUTED_PUBLISHER_KEY_ID,
                        AppBundleSignature.SIGNATURE_ALGORITHM,
                        substitutedPublisher.getPublic())));
    AppBundleVerifier verifier = AppBundleVerifier.requireSigned(trustedKeys);
    LocalProcessAppHost host = exactIdentityHost(layout(), verifier, trustedKeys);
    Path approved =
        stageInstalledAppAt(
            tempDir.resolve("approved-catalog-bundle"),
            SAMPLE_APP_ID,
            APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    AppBundleSigner.sign(approved, APPROVED_PUBLISHER_KEY_ID, approvedPublisher.getPrivate());
    AppBundleVerification approvedVerification = verifier.verify(approved);
    Path substituted =
        stageInstalledAppAt(
            tempDir.resolve("substituted-catalog-bundle"),
            SAMPLE_APP_ID,
            APP_VERSION,
            "#!/bin/sh\nexit 1\n",
            Map.of());
    AppBundleSigner.sign(
        substituted, SUBSTITUTED_PUBLISHER_KEY_ID, substitutedPublisher.getPrivate());
    InstalledAppOrigin approvedOrigin = signedOrigin(approvedVerification);

    assertThrows(
        AppHostException.class,
        () -> host.installCatalogFromDirectory(substituted, approvedOrigin));

    assertTrue(host.describe(SAMPLE_APP_ID).isEmpty());
    assertTrue(host.catalogOrigin(SAMPLE_APP_ID).isEmpty());
  }

  @Test
  void installCatalogFromDirectory_whenSignedContentDiffersFromOrigin_expectNoBundleCommitted()
      throws Exception {
    KeyPair publisher = generateEd25519KeyPair();
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(
            new TrustedAppKey(
                APPROVED_PUBLISHER_KEY_ID,
                AppBundleSignature.SIGNATURE_ALGORITHM,
                publisher.getPublic()));
    AppBundleVerifier verifier = AppBundleVerifier.requireSigned(trustedKeys);
    LocalProcessAppHost host = exactIdentityHost(layout(), verifier, trustedKeys);
    Path approved =
        stageInstalledAppAt(
            tempDir.resolve("approved-signed-content"),
            SAMPLE_APP_ID,
            APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    AppBundleSigner.sign(approved, APPROVED_PUBLISHER_KEY_ID, publisher.getPrivate());
    InstalledAppOrigin approvedOrigin = signedOrigin(verifier.verify(approved));
    Path substituted =
        stageInstalledAppAt(
            tempDir.resolve("substituted-signed-content"),
            SAMPLE_APP_ID,
            APP_VERSION,
            "#!/bin/sh\nexit 1\n",
            Map.of());
    AppBundleSigner.sign(substituted, APPROVED_PUBLISHER_KEY_ID, publisher.getPrivate());

    assertThrows(
        AppHostException.class,
        () -> host.installCatalogFromDirectory(substituted, approvedOrigin));

    assertTrue(host.describe(SAMPLE_APP_ID).isEmpty());
    assertTrue(host.catalogOrigin(SAMPLE_APP_ID).isEmpty());
  }

  @Test
  void rollback_whenRetainedSignerAndContentDifferFromOrigin_expectNoMutation() throws Exception {
    KeyPair approvedPublisher = generateEd25519KeyPair();
    KeyPair substitutedPublisher = generateEd25519KeyPair();
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(
                new TrustedAppKey(
                    APPROVED_PUBLISHER_KEY_ID,
                    AppBundleSignature.SIGNATURE_ALGORITHM,
                    approvedPublisher.getPublic()))
            .plus(
                TrustedAppKeys.of(
                    new TrustedAppKey(
                        SUBSTITUTED_PUBLISHER_KEY_ID,
                        AppBundleSignature.SIGNATURE_ALGORITHM,
                        substitutedPublisher.getPublic())));
    AppBundleVerifier verifier = AppBundleVerifier.requireSigned(trustedKeys);
    AppHostLayout appHostLayout = layout();
    LocalProcessAppHost host = exactIdentityHost(appHostLayout, verifier, trustedKeys);
    Path initial =
        stageInstalledAppAt(
            tempDir.resolve("catalog-rollback-approved"),
            SAMPLE_APP_ID,
            APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    AppBundleSigner.sign(initial, APPROVED_PUBLISHER_KEY_ID, approvedPublisher.getPrivate());
    InstalledAppOrigin initialOrigin = signedOrigin(verifier.verify(initial));
    host.installCatalogFromDirectory(initial, initialOrigin);
    Path update =
        stageInstalledAppAt(
            tempDir.resolve("catalog-rollback-current"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    AppBundleSigner.sign(update, APPROVED_PUBLISHER_KEY_ID, approvedPublisher.getPrivate());
    InstalledAppOrigin updateOrigin =
        signedOrigin(
            UPDATED_APP_VERSION, verifier.verify(update), initialOrigin.selfDigestSha256());
    host.updateCatalogFromDirectory(SAMPLE_APP_ID, update, updateOrigin);
    Path rollbackRoot = appHostLayout.rollbackAppsDir().resolve(SAMPLE_APP_ID);
    Files.writeString(
        rollbackRoot.resolve("substituted-content.txt"),
        "different retained bytes\n",
        StandardCharsets.UTF_8);
    AppBundleSigner.sign(
        rollbackRoot, SUBSTITUTED_PUBLISHER_KEY_ID, substitutedPublisher.getPrivate());
    AtomicBoolean authorizationInvoked = new AtomicBoolean();

    assertThrows(
        AppHostException.class,
        () ->
            host.rollback(
                SAMPLE_APP_ID,
                _ -> {
                  authorizationInvoked.set(true);
                  return () -> {};
                }));

    assertFalse(authorizationInvoked.get());
    assertEquals(
        UPDATED_APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertEquals(updateOrigin, host.catalogOrigin(SAMPLE_APP_ID).orElseThrow());
  }

  @Test
  void updateFromDirectory_whenCatalogOriginTracked_expectOriginRotatesWithBundle()
      throws IOException {
    LocalProcessAppHost host = developmentHost(layout());
    Path initial = stageInstalledApp(SAMPLE_APP_ID, EXIT_ZERO_SCRIPT, Map.of());
    InstalledAppOrigin initialOrigin = origin(APP_VERSION);
    host.installCatalogFromDirectory(initial, initialOrigin);
    assertFalse(host.rollbackRequiresCatalogAuthorization(SAMPLE_APP_ID));
    Path update =
        stageInstalledAppAt(
            tempDir.resolve("generic-update-over-catalog"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());

    host.updateFromDirectory(SAMPLE_APP_ID, update);

    assertTrue(host.catalogOrigin(SAMPLE_APP_ID).isEmpty());
    assertTrue(host.rollbackRequiresCatalogAuthorization(SAMPLE_APP_ID));
    assertEquals(
        UPDATED_APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());

    host.rollback(SAMPLE_APP_ID, _ -> () -> {});

    assertEquals(initialOrigin, host.catalogOrigin(SAMPLE_APP_ID).orElseThrow());
    assertFalse(host.rollbackRequiresCatalogAuthorization(SAMPLE_APP_ID));
    assertEquals(APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
  }

  @Test
  void catalogMutations_whenOriginsRotateAndUninstall_expectRetentionMatchesBothSlots()
      throws IOException {
    LocalProcessAppHost host = developmentHost(layout());
    List<List<InstalledAppOrigin>> retainedSnapshots = new ArrayList<>();
    host.setCatalogOriginRetention(
        new AppHost.CatalogOriginRetention() {
          @Override
          public void retain(List<InstalledAppOrigin> origins) {
            retainedSnapshots.add(List.copyOf(origins));
          }

          @Override
          public void reconcile(List<InstalledAppOrigin> origins) {
            retainedSnapshots.add(List.copyOf(origins));
          }
        });
    InstalledAppOrigin initialOrigin = origin(APP_VERSION);
    host.installCatalogFromDirectory(stageInstalledApp(SAMPLE_APP_ID), initialOrigin);
    Path update =
        stageInstalledAppAt(
            tempDir.resolve("catalog-origin-retention-update"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    InstalledAppOrigin updateOrigin = origin(UPDATED_APP_VERSION, initialOrigin.selfDigestSha256());

    host.updateCatalogFromDirectory(SAMPLE_APP_ID, update, updateOrigin);
    List<InstalledAppOrigin> updatedOrigins = retainedSnapshots.getLast();
    host.uninstall(SAMPLE_APP_ID);

    assertEquals(2, updatedOrigins.size());
    assertTrue(updatedOrigins.contains(initialOrigin));
    assertTrue(updatedOrigins.contains(updateOrigin));
    assertTrue(retainedSnapshots.getLast().isEmpty());
  }

  @Test
  void installCatalogFromDirectory_whenRetentionFails_expectPriorPinsReconciled()
      throws IOException {
    LocalProcessAppHost host = developmentHost(layout());
    List<List<InstalledAppOrigin>> retainedSnapshots = new ArrayList<>();
    AtomicBoolean rejectNextNonEmptySnapshot = new AtomicBoolean(true);
    host.setCatalogOriginRetention(
        new AppHost.CatalogOriginRetention() {
          @Override
          public void retain(List<InstalledAppOrigin> origins) throws IOException {
            retainedSnapshots.add(List.copyOf(origins));
            if (!origins.isEmpty() && rejectNextNonEmptySnapshot.getAndSet(false)) {
              throw new IOException("simulated catalog revision retention failure");
            }
          }

          @Override
          public void reconcile(List<InstalledAppOrigin> origins) {
            retainedSnapshots.add(List.copyOf(origins));
          }
        });
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    InstalledAppOrigin installedOrigin = origin(APP_VERSION);

    assertThrows(
        IOException.class, () -> host.installCatalogFromDirectory(stagedApp, installedOrigin));

    assertTrue(host.describe(SAMPLE_APP_ID).isEmpty());
    assertFalse(retainedSnapshots.get(1).isEmpty());
    assertTrue(retainedSnapshots.getLast().isEmpty());
  }

  @Test
  void installCatalogFromDirectory_whenPinCleanupFails_expectLaterReadRetries() throws IOException {
    LocalProcessAppHost host = developmentHost(layout());
    AtomicBoolean rejectFirstCommittedSnapshot = new AtomicBoolean(true);
    AtomicInteger reconciliationAttempts = new AtomicInteger();
    host.setCatalogOriginRetention(
        new AppHost.CatalogOriginRetention() {
          @Override
          public void retain(List<InstalledAppOrigin> origins) {
            // This test injects only a post-commit cleanup failure.
          }

          @Override
          public void reconcile(List<InstalledAppOrigin> origins) throws IOException {
            reconciliationAttempts.incrementAndGet();
            if (!origins.isEmpty() && rejectFirstCommittedSnapshot.getAndSet(false)) {
              throw new IOException("simulated stale catalog pin cleanup failure");
            }
          }
        });

    host.installCatalogFromDirectory(stageInstalledApp(SAMPLE_APP_ID), origin(APP_VERSION));
    int attemptsAfterCommit = reconciliationAttempts.get();

    assertTrue(host.describe(SAMPLE_APP_ID).isPresent());
    assertEquals(attemptsAfterCommit + 1, reconciliationAttempts.get());
  }

  @Test
  void updateFromDirectory_whenOnlyDiscardedRollbackHasOrigin_expectOriginRemainsAbsent()
      throws IOException {
    LocalProcessAppHost host = developmentHost(layout());
    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID, EXIT_ZERO_SCRIPT, Map.of()));
    Path catalogUpdate =
        stageInstalledAppAt(
            tempDir.resolve("catalog-update-from-legacy"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    InstalledAppOrigin catalogOrigin = origin(UPDATED_APP_VERSION);
    host.updateCatalogFromDirectory(
        SAMPLE_APP_ID, catalogUpdate, catalogOrigin, AppHost.CatalogOriginExpectation.absent());
    assertFalse(host.rollbackRequiresCatalogAuthorization(SAMPLE_APP_ID));
    host.rollback(SAMPLE_APP_ID);
    Path genericUpdate =
        stageInstalledAppAt(
            tempDir.resolve("generic-update-discarding-catalog-rollback"),
            SAMPLE_APP_ID,
            SECOND_UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());

    host.updateFromDirectory(SAMPLE_APP_ID, genericUpdate);
    host.rollback(SAMPLE_APP_ID);

    assertTrue(host.catalogOrigin(SAMPLE_APP_ID).isEmpty());
    assertEquals(APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
  }

  @Test
  void updateCatalogFromDirectory_whenExpectedOriginIsStale_expectNoMutation() throws IOException {
    LocalProcessAppHost host = developmentHost(layout());
    Path initial = stageInstalledApp(SAMPLE_APP_ID, EXIT_ZERO_SCRIPT, Map.of());
    InstalledAppOrigin initialOrigin = origin(APP_VERSION);
    host.installCatalogFromDirectory(initial, initialOrigin);
    Path update =
        stageInstalledAppAt(
            tempDir.resolve("stale-origin-update"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    InstalledAppOrigin updateOrigin = origin(UPDATED_APP_VERSION, initialOrigin.selfDigestSha256());

    assertThrows(
        AppHostException.CatalogOriginChangedException.class,
        () ->
            host.updateCatalogFromDirectory(
                SAMPLE_APP_ID,
                update,
                updateOrigin,
                AppHost.CatalogOriginExpectation.matching("2".repeat(64))));

    assertEquals(initialOrigin, host.catalogOrigin(SAMPLE_APP_ID).orElseThrow());
    assertEquals(APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertTrue(host.rollbackStatus(SAMPLE_APP_ID).isEmpty());
  }

  @Test
  void rollback_whenCatalogUpdateCommitted_expectBundleAndOriginRestoreTogether()
      throws IOException {
    LocalProcessAppHost host = developmentHost(layout());
    Path initial = stageInstalledApp(SAMPLE_APP_ID, EXIT_ZERO_SCRIPT, Map.of());
    InstalledAppOrigin initialOrigin = origin(APP_VERSION);
    host.installCatalogFromDirectory(initial, initialOrigin);
    Path update =
        stageInstalledAppAt(
            tempDir.resolve("catalog-update-rollback"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    InstalledAppOrigin updateOrigin = origin(UPDATED_APP_VERSION, initialOrigin.selfDigestSha256());
    host.updateCatalogFromDirectory(SAMPLE_APP_ID, update, updateOrigin);

    InstalledAppSnapshot restored = host.rollback(SAMPLE_APP_ID, _ -> () -> {});

    assertEquals(APP_VERSION, restored.manifest().appVersion());
    assertEquals(initialOrigin, host.catalogOrigin(SAMPLE_APP_ID).orElseThrow());
  }

  @Test
  void rollback_whenCatalogAuthorizationAccepts_expectExactRollbackOriginPassedInsideMutation()
      throws IOException {
    AppHostLayout layout = layout();
    LocalProcessAppHost host = developmentHost(layout);
    Path initial = stageInstalledApp(SAMPLE_APP_ID, EXIT_ZERO_SCRIPT, Map.of());
    InstalledAppOrigin initialOrigin = origin(APP_VERSION);
    host.installCatalogFromDirectory(initial, initialOrigin);
    Path update =
        stageInstalledAppAt(
            tempDir.resolve("authorized-catalog-rollback"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    InstalledAppOrigin updateOrigin = origin(UPDATED_APP_VERSION, initialOrigin.selfDigestSha256());
    host.updateCatalogFromDirectory(SAMPLE_APP_ID, update, updateOrigin);
    AtomicReference<InstalledAppOrigin> authorized = new AtomicReference<>();
    AtomicBoolean committedBeforeLeaseClosed = new AtomicBoolean();

    InstalledAppSnapshot restored =
        host.rollback(
            SAMPLE_APP_ID,
            rollbackOrigin -> {
              authorized.set(rollbackOrigin);
              return () -> {
                try {
                  String committedOrigin =
                      Files.readString(
                          layout.appOriginProvenanceDir().resolve(SAMPLE_APP_ID + ".properties"));
                  committedBeforeLeaseClosed.set(
                      committedOrigin.contains("appVersion=" + APP_VERSION + "\n"));
                } catch (IOException _) {
                  throw new AssertionError("catalog origin was unreadable while closing the lease");
                }
              };
            });

    assertEquals(initialOrigin, authorized.get());
    assertTrue(committedBeforeLeaseClosed.get());
    assertEquals(APP_VERSION, restored.manifest().appVersion());
    assertEquals(initialOrigin, host.catalogOrigin(SAMPLE_APP_ID).orElseThrow());
  }

  @Test
  void rollback_whenCatalogOriginExistsAndAuthorizationIsMissing_expectNoMutation()
      throws IOException {
    LocalProcessAppHost host = developmentHost(layout());
    Path initial = stageInstalledApp(SAMPLE_APP_ID, EXIT_ZERO_SCRIPT, Map.of());
    InstalledAppOrigin initialOrigin = origin(APP_VERSION);
    host.installCatalogFromDirectory(initial, initialOrigin);
    Path update =
        stageInstalledAppAt(
            tempDir.resolve("unauthorized-catalog-rollback"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    InstalledAppOrigin updateOrigin = origin(UPDATED_APP_VERSION, initialOrigin.selfDigestSha256());
    host.updateCatalogFromDirectory(SAMPLE_APP_ID, update, updateOrigin);

    assertThrows(
        AppHostException.CatalogRollbackAuthorizationException.class,
        () -> host.rollback(SAMPLE_APP_ID));

    assertEquals(
        UPDATED_APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertEquals(updateOrigin, host.catalogOrigin(SAMPLE_APP_ID).orElseThrow());
  }

  @Test
  void rollback_whenPriorBundlePredatesOriginTracking_expectUntrackedSlotRestoredAndSwapped()
      throws IOException {
    LocalProcessAppHost host = developmentHost(layout());
    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID, EXIT_ZERO_SCRIPT, Map.of()));
    Path update =
        stageInstalledAppAt(
            tempDir.resolve("catalog-update-over-untracked-bundle"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    InstalledAppOrigin updateOrigin = origin(UPDATED_APP_VERSION);
    host.updateCatalogFromDirectory(
        SAMPLE_APP_ID, update, updateOrigin, AppHost.CatalogOriginExpectation.absent());
    AtomicReference<InstalledAppOrigin> firstAuthorizedOrigin = new AtomicReference<>();

    InstalledAppSnapshot legacy =
        host.rollback(
            SAMPLE_APP_ID,
            rollbackOrigin -> {
              firstAuthorizedOrigin.set(rollbackOrigin);
              return () -> {};
            });

    assertEquals(APP_VERSION, legacy.manifest().appVersion());
    assertTrue(host.catalogOrigin(SAMPLE_APP_ID).isEmpty());
    assertNull(firstAuthorizedOrigin.get());

    AtomicReference<InstalledAppOrigin> secondAuthorizedOrigin = new AtomicReference<>();
    InstalledAppSnapshot catalog =
        host.rollback(
            SAMPLE_APP_ID,
            rollbackOrigin -> {
              secondAuthorizedOrigin.set(rollbackOrigin);
              return () -> {};
            });

    assertEquals(UPDATED_APP_VERSION, catalog.manifest().appVersion());
    assertEquals(updateOrigin, secondAuthorizedOrigin.get());
    assertEquals(updateOrigin, host.catalogOrigin(SAMPLE_APP_ID).orElseThrow());
  }

  @Test
  void rollback_whenCatalogAuthorizationRejects_expectBundleAndOriginsRemainUnchanged()
      throws IOException {
    LocalProcessAppHost host = developmentHost(layout());
    Path initial = stageInstalledApp(SAMPLE_APP_ID, EXIT_ZERO_SCRIPT, Map.of());
    InstalledAppOrigin initialOrigin = origin(APP_VERSION);
    host.installCatalogFromDirectory(initial, initialOrigin);
    Path update =
        stageInstalledAppAt(
            tempDir.resolve("rejected-catalog-rollback"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());
    InstalledAppOrigin updateOrigin = origin(UPDATED_APP_VERSION, initialOrigin.selfDigestSha256());
    host.updateCatalogFromDirectory(SAMPLE_APP_ID, update, updateOrigin);

    assertThrows(
        AppHostException.CatalogRollbackAuthorizationException.class,
        () ->
            host.rollback(
                SAMPLE_APP_ID,
                _ -> {
                  throw new AppHostException.CatalogRollbackAuthorizationException();
                }));

    assertEquals(
        UPDATED_APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertEquals(updateOrigin, host.catalogOrigin(SAMPLE_APP_ID).orElseThrow());
    assertEquals(APP_VERSION, host.rollbackStatus(SAMPLE_APP_ID).orElseThrow().appVersion());
  }

  @Test
  void catalogOrigin_whenCatalogUpdateTransactionWasInterrupted_expectPriorStateRecovered()
      throws IOException {
    AppHostLayout layout = layout();
    LocalProcessAppHost firstHost = developmentHost(layout);
    Path initial = stageInstalledApp(SAMPLE_APP_ID, EXIT_ZERO_SCRIPT, Map.of());
    InstalledAppOrigin initialOrigin = origin(APP_VERSION);
    firstHost.installCatalogFromDirectory(initial, initialOrigin);
    Path active = createActiveTransaction(layout, initialOrigin, true);
    InstalledAppOrigin attemptedOrigin =
        origin(UPDATED_APP_VERSION, initialOrigin.selfDigestSha256());
    new FileInstalledAppOriginStore(layout.appOriginProvenanceDir()).put(attemptedOrigin);

    LocalProcessAppHost recoveredHost = developmentHost(layout);

    assertEquals(initialOrigin, recoveredHost.catalogOrigin(SAMPLE_APP_ID).orElseThrow());
    assertEquals(
        APP_VERSION, recoveredHost.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertFalse(Files.exists(active));
  }

  @Test
  void catalogOrigin_whenCatalogInstallTransactionWasInterrupted_expectStaleOriginRemoved()
      throws IOException {
    AppHostLayout layout = layout();
    Path active = createActiveTransaction(layout, null, false);
    InstalledAppOrigin attemptedOrigin = origin(APP_VERSION);
    new FileInstalledAppOriginStore(layout.appOriginProvenanceDir()).put(attemptedOrigin);

    LocalProcessAppHost recoveredHost = developmentHost(layout);

    assertTrue(recoveredHost.catalogOrigin(SAMPLE_APP_ID).isEmpty());
    assertTrue(recoveredHost.describe(SAMPLE_APP_ID).isEmpty());
    assertFalse(Files.exists(active));
  }

  @Test
  void catalogOrigin_whenRepairTransactionCapturedUnreadableBundle_expectExactBytesRecovered()
      throws IOException {
    AppHostLayout layout = layout();
    LocalProcessAppHost firstHost = developmentHost(layout);
    InstalledAppSnapshot installation =
        firstHost.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Files.writeString(
        installation.paths().manifestFile(), "damaged manifest\n", StandardCharsets.UTF_8);
    Path marker = installation.paths().installedRoot().resolve("repair-marker.txt");
    Files.writeString(marker, "before repair\n", StandardCharsets.UTF_8);
    Path active = createActiveTransaction(layout, null, true);
    Files.writeString(marker, "attempted repair\n", StandardCharsets.UTF_8);
    LocalProcessAppHost recoveredHost = developmentHost(layout);

    assertTrue(recoveredHost.catalogOrigin(SAMPLE_APP_ID).isEmpty());

    assertEquals("before repair\n", Files.readString(marker, StandardCharsets.UTF_8));
    assertFalse(Files.exists(active));
    Path repairedStage =
        stageInstalledAppAt(
            tempDir.resolve("recovered-repair-stage"),
            SAMPLE_APP_ID,
            UPDATED_APP_VERSION,
            EXIT_ZERO_SCRIPT,
            Map.of());

    InstalledAppSnapshot repaired = recoveredHost.updateFromDirectory(SAMPLE_APP_ID, repairedStage);

    assertEquals(UPDATED_APP_VERSION, repaired.manifest().appVersion());
  }

  @Test
  void installCatalogFromDirectory_whenCommittedCleanupFails_expectLaterReadRetriesCleanup()
      throws IOException {
    AppHostLayout appHostLayout = layout();
    AtomicInteger cleanupAttempts = new AtomicInteger();
    LocalProcessAppHost host =
        new LocalProcessAppHost(
            appHostLayout,
            Duration.ofSeconds(1),
            new java.security.SecureRandom(),
            new AppEnv(),
            TEST_TIMING,
            _ -> {
              cleanupAttempts.incrementAndGet();
              throw new IOException("simulated committed transaction cleanup failure");
            },
            AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly());

    InstalledAppSnapshot installed =
        host.installCatalogFromDirectory(stageInstalledApp(SAMPLE_APP_ID), origin(APP_VERSION));

    assertEquals(1, cleanupAttempts.get());
    assertTrue(hasCommittedTransaction(appHostLayout));
    assertEquals(List.of(installed), host.listInstalled());
    assertFalse(hasCommittedTransaction(appHostLayout));
  }

  @Test
  void updateFromDirectory_whenAppIsRunning_expectFailure() throws IOException {
    AppHostLayout appHostLayout = layout();
    AppHost host = developmentHost(appHostLayout);
    host.installFromDirectory(stageInstalledRunnerApp(DAEMONIZED_CHILD_PROCESS_SCRIPT));
    host.start(RUNNER_APP_ID);
    Path transactionRoot = Files.createDirectories(appHostLayout.appMutationTransactionsDir());

    try (WatchService watchService = watchForCreatedEntries(transactionRoot)) {
      AppHostException exception =
          assertThrows(
              AppHostException.class,
              () ->
                  host.updateFromDirectory(
                      RUNNER_APP_ID, tempDir.resolve(STAGE_DIR_NAME).resolve(RUNNER_APP_ID)));

      assertEquals("cannot update a running app: " + RUNNER_APP_ID, exception.getMessage());
      assertEquals(APP_VERSION, host.describe(RUNNER_APP_ID).orElseThrow().manifest().appVersion());
      assertNoCreatedEntry(watchService, transactionRoot);
    } finally {
      host.stop(RUNNER_APP_ID);
    }
  }

  @Test
  void updateFromDirectory_whenRestartPending_expectAcceptedUpdateCancelsRestart()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp = stageInstalledRunnerApp(RESTART_ON_FAILURE_SCRIPT);
    appendOnFailureRestartPolicy(stagedApp, 750);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    host.start(RUNNER_APP_ID);
    waitForRuntimeState(host, AppRuntimeState.RESTARTING);
    Path updatedRunMarker = installation.paths().runDir().resolve("updated-ran.txt");
    Path updatedStage =
        stageInstalledAppAt(
            tempDir.resolve("stage-update-restarting").resolve(RUNNER_APP_ID),
            RUNNER_APP_ID,
            UPDATED_APP_VERSION,
            """
            #!/bin/sh
            set -eu
            printf 'updated\\n' > "$CRYPTAD_APP_RUN_DIR/updated-ran.txt"
            exit 0
            """,
            Map.of());

    InstalledAppSnapshot updated = host.updateFromDirectory(RUNNER_APP_ID, updatedStage);
    LockSupport.parkNanos(Duration.ofSeconds(1).toNanos());

    assertEquals(UPDATED_APP_VERSION, updated.manifest().appVersion());
    assertFalse(Files.exists(updatedRunMarker));
    assertEquals(AppRuntimeState.STOPPED, host.runtimeStatus(RUNNER_APP_ID).state());
  }

  @Test
  void updateFromDirectory_whenStagedDirectoryInvalid_expectFailure() throws IOException {
    AppHostLayout appHostLayout = layout();
    AppHost host = developmentHost(appHostLayout);
    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Path transactionRoot = Files.createDirectories(appHostLayout.appMutationTransactionsDir());

    try (WatchService watchService = watchForCreatedEntries(transactionRoot)) {
      AppHostException exception =
          assertThrows(
              AppHostException.class,
              () -> host.updateFromDirectory(SAMPLE_APP_ID, tempDir.resolve("missing-stage")));

      assertTrue(
          exception.getMessage().contains("stagedAppDirectory must be an existing directory"));
      assertEquals(APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
      assertNoCreatedEntry(watchService, transactionRoot);
    }
  }

  @Test
  void installFromDirectory_whenInstalledAppsDirIsSymlink_expectFailure() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Path dataDir = tempDir.resolve("data");
    Path cacheDir = tempDir.resolve(CACHE_DIR_NAME);
    Path runDir = tempDir.resolve("run");
    AppHost host =
        new LocalProcessAppHost(
            new AppHostLayout(dataDir, cacheDir, runDir),
            Duration.ofSeconds(1),
            new java.security.SecureRandom(),
            AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly());
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    Path installParent = Files.createDirectories(dataDir.resolve("apps"));
    Path externalInstalled = Files.createDirectories(tempDir.resolve("external-installed"));
    Files.createSymbolicLink(
        installParent.resolve(INSTALLED_DIR_NAME), externalInstalled.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains(INSTALLED_APPS_DIR_SYMLINK_MESSAGE));
    try (var children = Files.list(externalInstalled)) {
      assertEquals(List.of(), children.toList());
    }
  }

  @Test
  void uninstall_whenInstalledAppsDirBecomesSymlink_expectFailureBeforeDeletingExternalBundle()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Path dataDir = tempDir.resolve("data");
    Path cacheDir = tempDir.resolve(CACHE_DIR_NAME);
    Path runDir = tempDir.resolve("run");
    AppHost host =
        new LocalProcessAppHost(
            new AppHostLayout(dataDir, cacheDir, runDir),
            Duration.ofSeconds(1),
            new java.security.SecureRandom(),
            AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly());

    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));

    Path installParent = dataDir.resolve("apps");
    Path installedAppsDir = installParent.resolve(INSTALLED_DIR_NAME);
    Path externalInstalled = tempDir.resolve("external-installed");
    Files.move(installedAppsDir, externalInstalled);
    Files.createSymbolicLink(installedAppsDir, externalInstalled.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.uninstall(SAMPLE_APP_ID));

    assertTrue(exception.getMessage().contains(INSTALLED_APPS_DIR_SYMLINK_MESSAGE));
    assertTrue(Files.isDirectory(externalInstalled.resolve(SAMPLE_APP_ID)));
    assertTrue(
        Files.isRegularFile(externalInstalled.resolve(SAMPLE_APP_ID).resolve(CONTENT_FILE_NAME)));
  }

  @Test
  void uninstall_whenInstalledAppsAncestorBecomesSymlink_expectFailureBeforeDeletingExternalBundle()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Path dataDir = tempDir.resolve("data");
    Path cacheDir = tempDir.resolve(CACHE_DIR_NAME);
    Path runDir = tempDir.resolve("run");
    AppHost host =
        new LocalProcessAppHost(
            new AppHostLayout(dataDir, cacheDir, runDir),
            Duration.ofSeconds(1),
            new java.security.SecureRandom(),
            AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly());

    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));

    Path appsDir = dataDir.resolve("apps");
    Path externalAppsDir = tempDir.resolve("external-apps");
    Files.move(appsDir, externalAppsDir);
    Files.createSymbolicLink(appsDir, externalAppsDir.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.uninstall(SAMPLE_APP_ID));

    assertTrue(exception.getMessage().contains(INSTALLED_APPS_DIR_SYMLINK_MESSAGE));
    assertTrue(
        Files.isDirectory(externalAppsDir.resolve(INSTALLED_DIR_NAME).resolve(SAMPLE_APP_ID)));
    assertTrue(
        Files.isRegularFile(
            externalAppsDir
                .resolve(INSTALLED_DIR_NAME)
                .resolve(SAMPLE_APP_ID)
                .resolve(CONTENT_FILE_NAME)));
  }

  @Test
  void listInstalled_whenStaleTemporaryInstallDirectoryExists_expectInstalledAppsOnly()
      throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Path staleInstallDirectory =
        tempDir
            .resolve("data")
            .resolve("apps")
            .resolve(INSTALLED_DIR_NAME)
            .resolve("app-install-stale");
    Files.createDirectories(staleInstallDirectory);
    Files.writeString(
        staleInstallDirectory.resolve(CONTENT_FILE_NAME), "stale", StandardCharsets.UTF_8);

    assertEquals(List.of(installation), host.listInstalled());
  }

  @Test
  void installFromDirectory_whenPosixDirectExecutableLacksExecutePermission_expectFailure()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp =
        stageInstalledExecutableApp(
            "non-launchable-app",
            POSIX_LAUNCH_PATH,
            """
            exit 0
            """,
            Map.of(),
            false);

    Assumptions.assumeFalse(Files.isExecutable(stagedApp.resolve(POSIX_LAUNCH_PATH)));

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("without execute permission"));
  }

  @Test
  void installFromDirectory_whenWindowsLauncherUsesUnsupportedScript_expectFailure()
      throws IOException {
    AppHost host = allowUnsignedHost(Duration.ofSeconds(1), new AppEnv(Map.of(), WINDOWS_11));
    Path stagedApp =
        stageInstalledExecutableApp(
            "unsupported-windows-script-app", "bin/launch.ps1", "Write-Output 'hi'\n", Map.of());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("app.exec is not launchable on Windows"));
  }

  @Test
  void installFromDirectory_whenWindowsLauncherIsGenericMzBlob_expectFailure() throws IOException {
    AppHost host = allowUnsignedHost(Duration.ofSeconds(1), new AppEnv(Map.of(), WINDOWS_11));
    Path stagedApp =
        stageInstalledExecutableApp("generic-mz-app", "bin/fake.bin", "placeholder", Map.of());
    byte[] fakeMz = new byte[64];
    fakeMz[0] = 'M';
    fakeMz[1] = 'Z';
    Files.write(stagedApp.resolve("bin/fake.bin"), fakeMz);

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("app.exec is not launchable on Windows"));
  }

  @Test
  void lifecycle_whenManifestUsesMixedCaseAppId_expectPublicApiAcceptsOriginalCase()
      throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation =
        host.installFromDirectory(stageInstalledApp(MIXED_CASE_APP_ID));

    assertEquals(NORMALIZED_MIXED_CASE_APP_ID, installation.appId());
    assertEquals(
        installation.manifest(), host.describe(MIXED_CASE_APP_ID).orElseThrow().manifest());

    RunningAppSnapshot running = host.start(MIXED_CASE_APP_ID);

    assertEquals(NORMALIZED_MIXED_CASE_APP_ID, running.appId());
    assertEquals(running.token(), host.status(MIXED_CASE_APP_ID).orElseThrow().token());
    assertTrue(host.stop(MIXED_CASE_APP_ID));
    host.uninstall(MIXED_CASE_APP_ID);
    assertTrue(host.describe(NORMALIZED_MIXED_CASE_APP_ID).isEmpty());
  }

  @Test
  void lifecycle_whenInstalledScriptRuns_expectEnvTokenStopAndUninstall() throws IOException {
    AppHost host = allowUnsignedHost();
    Path stagedApp = stageInstalledApp(RUNNER_APP_ID);

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    assertFalse(running.token().isBlank());
    assertEquals(RUNNER_APP_ID, running.appId());
    assertEquals(running.token(), host.status(RUNNER_APP_ID).orElseThrow().token());
    List<RunningAppSnapshot> runningSnapshots = host.listRunning();
    assertEquals(1, runningSnapshots.size());
    assertEquals(running.appId(), runningSnapshots.getFirst().appId());
    assertEquals(running.token(), runningSnapshots.getFirst().token());

    Path captureFile = installation.paths().runDir().resolve("captured-env.txt");
    waitForFile(captureFile);
    String capture = Files.readString(captureFile, StandardCharsets.UTF_8);
    assertCapturedEnvironment(installation, running, capture);

    assertThrows(AppHostException.class, () -> host.uninstall(RUNNER_APP_ID));
    assertTrue(host.stop(RUNNER_APP_ID));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());

    RunningAppSnapshot secondRun = host.start(RUNNER_APP_ID);
    assertNotEquals(running.token(), secondRun.token());
    assertTrue(host.stop(RUNNER_APP_ID));

    host.uninstall(RUNNER_APP_ID);
    assertInstallationPathsRemoved(installation);
    assertTrue(host.listInstalled().isEmpty());
  }

  @Test
  void mailEndpointRequiresHostSelectedLoopbackAndCannotChangeDuringLaunch() throws IOException {
    LocalProcessAppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledApp("mail-prototype"));
    assertThrows(AppHostException.class, () -> host.start("mail-prototype"));
    URI remoteEndpoint = URI.create("http://example.com:8888/api/v1");
    assertThrows(
        IllegalArgumentException.class, () -> host.setMailPlatformApiEndpoint(remoteEndpoint));
    URI invalidPathEndpoint = URI.create("http://127.0.0.1:8888/arbitrary");
    assertThrows(
        IllegalArgumentException.class, () -> host.setMailPlatformApiEndpoint(invalidPathEndpoint));
    URI endpoint = URI.create("http://127.0.0.1:8888/api/v1");
    host.setMailPlatformApiEndpoint(endpoint);
    RunningAppSnapshot running = host.start("mail-prototype");
    try {
      Path captureFile = running.paths().runDir().resolve("captured-env.txt");
      waitForFile(captureFile);
      AppEnv environment = new AppEnv();
      Path expectedJava =
          environment
              .javaHome()
              .toRealPath()
              .resolve("bin")
              .resolve(environment.isWindows() ? "java.exe" : "java");
      assertTrue(Files.readString(captureFile).contains("CRYPTAD_MAIL_JAVA=" + expectedJava));
      assertTrue(host.currentLaunch("mail-prototype").isPresent());
      assertFalse(
          host.currentLaunch("mail-prototype").orElseThrow().toString().contains(running.token()));
      assertThrows(IllegalArgumentException.class, () -> host.setMailPlatformApiEndpoint(endpoint));
    } finally {
      host.stop("mail-prototype");
    }
    assertTrue(host.currentLaunch("mail-prototype").isEmpty());
  }

  @Test
  void authenticateLaunchToken_whenTokenBelongsToRunningApp_expectTokenFreePrincipal()
      throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    try {
      AppTokenPrincipal principal = host.authenticateLaunchToken(running.token()).orElseThrow();

      assertEquals(RUNNER_APP_ID, principal.appId());
      assertFalse(principal.launchId().isEmpty());
      assertEquals(principal, host.currentLaunch(RUNNER_APP_ID).orElseThrow());
      assertEquals(
          List.of(FILE_READ_PERMISSION, NETWORK_ACCESS_PERMISSION), principal.permissions());
      assertFalse(principal.toString().contains(running.token()));
    } finally {
      host.stop(RUNNER_APP_ID);
    }
  }

  @Test
  void authenticateLaunchToken_whenTokenIsBlankOrUnknown_expectEmpty() throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    try {
      assertTrue(host.authenticateLaunchToken("").isEmpty());
      assertTrue(host.authenticateLaunchToken("   ").isEmpty());
      assertTrue(host.authenticateLaunchToken(null).isEmpty());
      assertTrue(host.authenticateLaunchToken(running.token() + "-unknown").isEmpty());
    } finally {
      host.stop(RUNNER_APP_ID);
    }
  }

  @Test
  void authenticateLaunchToken_whenAppStops_expectOldTokenFails() throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    assertTrue(host.authenticateLaunchToken(running.token()).isPresent());
    assertTrue(host.stop(RUNNER_APP_ID));

    assertTrue(host.authenticateLaunchToken(running.token()).isEmpty());
  }

  @Test
  void authenticateLaunchToken_whenAppRestarts_expectOldTokenFailsAndNewTokenSucceeds()
      throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    RunningAppSnapshot firstRun = host.start(RUNNER_APP_ID);
    String firstLaunch = host.currentLaunch(RUNNER_APP_ID).orElseThrow().launchId();
    assertTrue(host.stop(RUNNER_APP_ID));
    assertTrue(host.currentLaunch(RUNNER_APP_ID).isEmpty());

    RunningAppSnapshot secondRun = host.start(RUNNER_APP_ID);

    try {
      assertNotEquals(firstRun.token(), secondRun.token());
      assertNotEquals(firstLaunch, host.currentLaunch(RUNNER_APP_ID).orElseThrow().launchId());
      assertTrue(host.authenticateLaunchToken(firstRun.token()).isEmpty());
      assertEquals(
          RUNNER_APP_ID, host.authenticateLaunchToken(secondRun.token()).orElseThrow().appId());
    } finally {
      host.stop(RUNNER_APP_ID);
    }
  }

  @Test
  void authenticateLaunchToken_whenReturningPermissions_expectImmutableSortedManifestPermissions()
      throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    try {
      AppTokenPrincipal principal = host.authenticateLaunchToken(running.token()).orElseThrow();
      List<String> permissions = principal.permissions();

      assertEquals(List.of(FILE_READ_PERMISSION, NETWORK_ACCESS_PERMISSION), permissions);
      assertThrows(UnsupportedOperationException.class, () -> permissions.add("extra"));
    } finally {
      host.stop(RUNNER_APP_ID);
    }
  }

  @Test
  void start_whenAppRuns_expectWorkingDirectoryRuntimeStatusAndRedactedLog() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation =
        host.installFromDirectory(stageInstalledRunnerApp(WORKING_DIRECTORY_AND_TOKEN_LOG_SCRIPT));

    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    Path cwdFile = installation.paths().runDir().resolve("cwd.txt");
    waitForFile(cwdFile);
    waitForFile(installation.paths().processLogFile());
    assertEquals(
        installation.paths().installedRoot().toString(),
        Files.readString(cwdFile, StandardCharsets.UTF_8).trim());

    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
    assertEquals(AppRuntimeState.RUNNING, status.state());
    assertTrue(status.running());
    assertNotNull(status.pid());
    assertTrue(status.logAvailable());

    AppProcessLogSnapshot logTail = host.readProcessLogTail(RUNNER_APP_ID, 4096);
    assertTrue(logTail.available());
    assertFalse(logTail.text().contains(running.token()));
    assertFalse(logTail.text().contains(installation.paths().installedRoot().toString()));
    assertFalse(logTail.text().contains(installation.paths().dataDir().toString()));
    assertFalse(logTail.text().contains(installation.paths().cacheDir().toString()));
    assertFalse(logTail.text().contains(installation.paths().runDir().toString()));
    assertFalse(logTail.text().contains(installation.paths().processLogFile().toString()));
    assertTrue(logTail.text().contains("cwd=[APP_INSTALL_DIR]"));
    assertTrue(logTail.text().contains("CRYPTAD_APP_DATA_DIR=[APP_DATA_DIR]"));
    assertTrue(logTail.text().contains("CRYPTAD_APP_CACHE_DIR=[APP_CACHE_DIR]"));
    assertTrue(logTail.text().contains("CRYPTAD_APP_RUN_DIR=[APP_RUN_DIR]"));
    assertTrue(logTail.text().contains("process-log=[APP_PROCESS_LOG]"));
    assertTrue(logTail.text().contains("CRYPTAD_APP_TOKEN=[REDACTED]"));
    assertTrue(logTail.text().contains("raw-token=[REDACTED]"));

    assertTrue(host.stop(RUNNER_APP_ID));
    assertEquals(AppRuntimeState.STOPPED, host.runtimeStatus(RUNNER_APP_ID).state());
  }

  @Test
  void start_whenInstalledProcessExitsImmediately_expectFailureAndNoRunningState()
      throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledRunnerApp(immediateExitScriptContent(new AppEnv())));

    Instant started = Instant.now();
    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));
    Duration elapsed = Duration.between(started, Instant.now());

    assertTrue(exception.getMessage().contains(STARTUP_EXIT_MESSAGE_PREFIX + RUNNER_APP_ID));
    assertTrue(elapsed.compareTo(Duration.ofSeconds(3)) < 0);
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
    assertEquals(AppRuntimeState.EXITED, status.state());
    assertEquals(0, status.lastExitCode());
  }

  @Test
  void start_whenInstalledProcessCrashesImmediately_expectCrashedRuntimeStatus()
      throws IOException {
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledRunnerApp(IMMEDIATE_CRASH_SCRIPT));

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    assertTrue(exception.getMessage().contains(STARTUP_EXIT_MESSAGE_PREFIX + RUNNER_APP_ID));
    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
    assertEquals(AppRuntimeState.CRASHED, status.state());
    assertEquals(7, status.lastExitCode());
  }

  @Test
  void processLogTail_whenExitedProcessPrintedRawToken_expectLastLaunchTokenRedacted()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledRunnerApp(IMMEDIATE_TOKEN_CRASH_SCRIPT));

    assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    AppProcessLogSnapshot logTail = host.readProcessLogTail(RUNNER_APP_ID, 4096);
    assertTrue(logTail.available());
    assertTrue(logTail.text().contains("raw-token=[REDACTED]"));
    assertFalse(logTail.text().matches("(?s).*raw-token=[0-9a-f]{64}.*"));
    AppProcessLogSnapshot smallLogTail = host.readProcessLogTail(RUNNER_APP_ID, 12);
    assertTrue(smallLogTail.available());
    assertFalse(smallLogTail.text().matches("(?s).*[0-9a-f]{8}.*"));
  }

  @Test
  void processLogTail_whenTailStartsInsideKnownPath_expectPathRedactedBeforeTrim()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    Files.writeString(
        installation.paths().processLogFile(),
        "path=" + installation.paths().dataDir() + "\n",
        StandardCharsets.UTF_8);

    AppProcessLogSnapshot logTail = host.readProcessLogTail(RUNNER_APP_ID, 16);

    assertTrue(logTail.available());
    assertTrue(logTail.truncated());
    assertTrue(logTail.text().contains("[APP_DATA_DIR]"));
    assertFalse(logTail.text().contains("/"));
    assertFalse(logTail.text().contains(installation.paths().dataDir().toString()));
  }

  @Test
  void processLogTail_whenUnknownTokenColonAssignmentIsSplit_expectAssignmentRedacted()
      throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    String assignment =
        APP_TOKEN_ENV_NAME + " ".repeat(16) + ":" + " ".repeat(16) + REDACTION_PROBE_VALUE;
    Files.writeString(installation.paths().processLogFile(), assignment, StandardCharsets.UTF_8);

    AppProcessLogSnapshot logTail = host.readProcessLogTail(RUNNER_APP_ID, 32);

    assertTrue(logTail.available());
    assertTrue(logTail.truncated());
    assertTrue(logTail.text().contains("[REDACTED]"));
    assertFalse(
        logTail
            .text()
            .contains(REDACTION_PROBE_VALUE.substring(REDACTION_PROBE_VALUE.length() - 32)));
    assertFalse(logTail.text().matches("(?s).*[0-9a-f]{8}.*"));
  }

  @Test
  void processLogTail_whenLogLimitWouldSplitTokenAssignment_expectOverlapRetainedAndRedacted()
      throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    String assignment = APP_TOKEN_ENV_ASSIGNMENT_PREFIX + REDACTION_PROBE_VALUE;
    int cutOffset = APP_TOKEN_ENV_ASSIGNMENT_PREFIX.length() + 8;
    int overlapBytes = AppHostTokenRedactor.redactionOverlapBytes(null, installation.paths());
    String prefix = "p".repeat(overlapBytes + 50);
    int tailBytes =
        Math.toIntExact(
            AppHost.DEFAULT_PROCESS_LOG_MAX_BYTES
                - assignment.getBytes(StandardCharsets.UTF_8).length
                + cutOffset);
    Files.writeString(
        installation.paths().processLogFile(),
        prefix + assignment + "z".repeat(tailBytes),
        StandardCharsets.UTF_8);

    AppProcessLogSnapshot logTail =
        host.readProcessLogTail(RUNNER_APP_ID, AppHost.MAX_PROCESS_LOG_TAIL_BYTES);

    assertTrue(logTail.available());
    assertTrue(logTail.truncated());
    assertEquals(processLogRetainedBytes(installation.paths()), logTail.sizeBytes());
    assertTrue(logTail.text().contains(APP_TOKEN_ENV_ASSIGNMENT_PREFIX + "[REDACTED]"));
    assertFalse(logTail.text().contains(REDACTION_PROBE_VALUE.substring(8)));
    assertFalse(logTail.text().matches("(?s).*[0-9a-f]{16}.*"));
  }

  @Test
  void processLogTail_whenMaxBytesSmall_expectTailIsBoundedAndRedacted() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation =
        host.installFromDirectory(stageInstalledRunnerApp(WORKING_DIRECTORY_AND_TOKEN_LOG_SCRIPT));
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);
    waitForFile(installation.paths().processLogFile());

    AppProcessLogSnapshot logTail = host.readProcessLogTail(RUNNER_APP_ID, 24);

    assertTrue(logTail.available());
    assertTrue(logTail.truncated());
    assertEquals(24, logTail.maxBytes());
    assertFalse(logTail.text().contains(running.token()));
    assertTrue(logTail.text().length() <= 64);
    assertTrue(host.stop(RUNNER_APP_ID));
  }

  @Test
  void start_whenDataUsageExceedsPositiveQuota_expectLaunchBlockedAndStatusWarns()
      throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    Files.writeString(
        installation.paths().dataDir().resolve("too-large.dat"),
        "x".repeat(4097),
        StandardCharsets.UTF_8);

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    assertEquals("app data quota exceeded: " + RUNNER_APP_ID, exception.getMessage());
    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
    assertTrue(status.quotaStatus().dataOverLimit());
    assertFalse(status.toString().contains(installation.paths().dataDir().toString()));
  }

  @Test
  void start_whenCacheUsageExceedsPositiveQuota_expectLaunchBlockedAndStatusWarns()
      throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    Files.writeString(
        installation.paths().cacheDir().resolve("too-large.dat"),
        "x".repeat(1025),
        StandardCharsets.UTF_8);

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    assertEquals("app cache quota exceeded: " + RUNNER_APP_ID, exception.getMessage());
    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
    assertTrue(status.quotaStatus().cacheOverLimit());
    assertFalse(status.toString().contains(installation.paths().cacheDir().toString()));
  }

  @Test
  void start_whenQuotaIsZeroOrAbsent_expectLaunchAllowed() throws IOException {
    AppHost zeroQuotaHost = allowUnsignedHost();
    Path zeroQuotaApp = stageInstalledApp(ZERO_QUOTA_APP_ID);
    replaceManifestQuotasWithZero(zeroQuotaApp);
    InstalledAppSnapshot zeroQuotaInstallation = zeroQuotaHost.installFromDirectory(zeroQuotaApp);
    Files.writeString(
        zeroQuotaInstallation.paths().dataDir().resolve("large.dat"),
        "x".repeat(8192),
        StandardCharsets.UTF_8);

    RunningAppSnapshot zeroQuotaRunning = zeroQuotaHost.start(ZERO_QUOTA_APP_ID);
    assertEquals(ZERO_QUOTA_APP_ID, zeroQuotaRunning.appId());
    assertFalse(zeroQuotaHost.runtimeStatus(ZERO_QUOTA_APP_ID).quotaStatus().dataQuotaEnforced());
    assertTrue(zeroQuotaHost.stop(ZERO_QUOTA_APP_ID));

    AppHost absentQuotaHost = allowUnsignedHost();
    Path absentQuotaApp = stageInstalledApp(ABSENT_QUOTA_APP_ID);
    removeManifestQuotas(absentQuotaApp);
    InstalledAppSnapshot absentQuotaInstallation =
        absentQuotaHost.installFromDirectory(absentQuotaApp);
    Files.writeString(
        absentQuotaInstallation.paths().cacheDir().resolve("large.dat"),
        "x".repeat(8192),
        StandardCharsets.UTF_8);

    RunningAppSnapshot absentQuotaRunning = absentQuotaHost.start(ABSENT_QUOTA_APP_ID);
    assertEquals(ABSENT_QUOTA_APP_ID, absentQuotaRunning.appId());
    assertFalse(
        absentQuotaHost.runtimeStatus(ABSENT_QUOTA_APP_ID).quotaStatus().cacheQuotaEnforced());
    assertTrue(absentQuotaHost.stop(ABSENT_QUOTA_APP_ID));
  }

  @Test
  void runtimeStatus_whenProcessLogExceedsHostLimit_expectTailTruncatedAndWarning()
      throws IOException {
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    String tail = "tail-marker\n";
    long retainedBytes = processLogRetainedBytes(installation.paths());
    Files.writeString(
        installation.paths().processLogFile(),
        "x".repeat(Math.toIntExact(retainedBytes + 128L)) + tail,
        StandardCharsets.UTF_8);

    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);

    assertEquals(retainedBytes, Files.size(installation.paths().processLogFile()));
    assertTrue(Files.readString(installation.paths().processLogFile()).endsWith(tail));
    assertEquals(retainedBytes, status.quotaStatus().usage().processLogSizeBytes());
    assertTrue(
        status
            .quotaStatus()
            .warningMessages()
            .contains("Process log exceeded the host limit and was truncated to its tail."));
  }

  @Test
  void stop_whenProcessLogExceedsHostLimit_expectTruncationWarningPreserved() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    host.start(RUNNER_APP_ID);
    String tail = "stop-tail-marker\n";
    long retainedBytes = processLogRetainedBytes(installation.paths());
    Files.writeString(
        installation.paths().processLogFile(),
        "x".repeat(Math.toIntExact(retainedBytes + 128L)) + tail,
        StandardCharsets.UTF_8);

    assertTrue(host.stop(RUNNER_APP_ID));

    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
    assertEquals(AppRuntimeState.STOPPED, status.state());
    assertEquals(retainedBytes, Files.size(installation.paths().processLogFile()));
    assertTrue(
        status
            .warnings()
            .contains("Process log exceeded the host limit and was truncated to its tail."));
  }

  @Test
  void restartPolicy_whenOnFailureConfigured_expectBoundedRestartAndVisibleAttempt()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp = stageInstalledRunnerApp(RESTART_ON_FAILURE_SCRIPT);
    appendOnFailureRestartPolicy(stagedApp, 10);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    host.start(RUNNER_APP_ID);

    Path runCountFile = installation.paths().runDir().resolve(RESTART_COUNT_FILE_NAME);
    waitForFileContent(runCountFile, "2\n");
    AppRuntimeStatusSnapshot status = waitForRuntimeState(host, AppRuntimeState.RUNNING);
    assertEquals(1, status.currentRestartAttempt());
    assertEquals(1, status.restartCount());
    assertEquals(7, status.lastExitCode());
    assertNotNull(status.lastExitAt());

    assertTrue(host.stop(RUNNER_APP_ID));
  }

  @Test
  void restartPolicy_whenHistoricalVerifierRejectsRelaunch_expectAutomaticRestartBlocked()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AtomicInteger historicalVerifications = new AtomicInteger();
    AppInstallVerificationPolicy verificationPolicy =
        AppInstallVerificationPolicy.requireSigned(
            _ -> {},
            _ -> {
              if (historicalVerifications.incrementAndGet() > 1) {
                throw new AppBundleVerificationException(
                    "installed app signing key was revoked before restart");
              }
            });
    LocalProcessAppHost host =
        new LocalProcessAppHost(
            layout(),
            Duration.ofSeconds(1),
            new java.security.SecureRandom(),
            appEnv,
            TEST_TIMING,
            verificationPolicy);
    Path stagedApp = stageInstalledRunnerApp(RESTART_ON_FAILURE_SCRIPT);
    appendOnFailureRestartPolicy(stagedApp, 10);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    host.start(RUNNER_APP_ID);

    Path runCountFile = installation.paths().runDir().resolve(RESTART_COUNT_FILE_NAME);
    waitForFileContent(runCountFile, "1\n");
    AppRuntimeStatusSnapshot status = waitForRuntimeState(host, AppRuntimeState.CRASHED);
    assertEquals(2, historicalVerifications.get());
    assertEquals(1, status.currentRestartAttempt());
    assertEquals(0, status.restartCount());
    assertTrue(
        status
            .warnings()
            .contains("Installed app bundle verification failed; automatic restart was blocked."));
    assertEquals("1\n", Files.readString(runCountFile, StandardCharsets.UTF_8));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
  }

  @Test
  void restartPolicy_whenShellWrapperWaitsForCleanChildExit_expectNoFailureRestart()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            WAITING_WRAPPER_CLEAN_EXIT_SCRIPT,
            Map.of(CHILD_SCRIPT_PATH, CLEAN_EXIT_CHILD_SCRIPT));
    appendOnFailureRestartPolicy(stagedApp, 10);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    host.start(RUNNER_APP_ID);

    Path runCountFile = installation.paths().runDir().resolve("wait-wrapper-run-count.txt");
    waitForFileContent(runCountFile, "1\n");
    AppRuntimeStatusSnapshot status = waitForRuntimeState(host, AppRuntimeState.EXITED);
    assertEquals(0, status.lastExitCode());
    assertEquals(0, status.currentRestartAttempt());
    assertEquals(0, status.restartCount());
    assertEquals("1\n", Files.readString(runCountFile, StandardCharsets.UTF_8));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
  }

  @Test
  void restartPolicy_whenCleanRootExitLeavesTransientChildHandle_expectNoFailureRestart()
      throws IOException, ReflectiveOperationException {
    LocalProcessAppHost host = allowUnsignedHost();
    Path stagedApp = stageInstalledRunnerApp(IMMEDIATE_CRASH_SCRIPT);
    appendOnFailureRestartPolicy(stagedApp, 10);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    Process process = new CleanExitedProcessWithTransientChild(101L, 102L, 2);
    RunningAppSnapshot snapshot =
        new RunningAppSnapshot(
            installation.manifest(),
            installation.paths(),
            DEFAULT_TOKEN,
            process.pid(),
            Instant.now());
    injectRunningProcess(
        host, RUNNER_APP_ID, snapshot, process, CompletableFuture.completedFuture(null));

    AppRuntimeStatusSnapshot runningStatus = host.runtimeStatus(RUNNER_APP_ID);
    assertEquals(AppRuntimeState.RUNNING, runningStatus.state());
    AppRuntimeStatusSnapshot status = waitForRuntimeState(host, AppRuntimeState.EXITED);

    assertEquals(0, status.lastExitCode());
    assertEquals(0, status.currentRestartAttempt());
    assertEquals(0, status.restartCount());
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
  }

  @Test
  void restartPolicy_whenObservedHandoffChildExitsAfterGrace_expectUnknownExitRestarts()
      throws IOException, ReflectiveOperationException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    LocalProcessAppHost host = allowUnsignedHost();
    Path stagedApp = stageInstalledRunnerApp(WORKING_DIRECTORY_AND_TOKEN_LOG_SCRIPT);
    appendOnFailureRestartPolicy(stagedApp, 10);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    ControlledProcessHandle childHandle = new ControlledProcessHandle(102L);
    Process process = new CleanExitedProcessWithTransientChild(101L, childHandle);
    RunningAppSnapshot snapshot =
        new RunningAppSnapshot(
            installation.manifest(),
            installation.paths(),
            DEFAULT_TOKEN,
            process.pid(),
            Instant.now());
    injectRunningProcess(
        host, RUNNER_APP_ID, snapshot, process, CompletableFuture.completedFuture(null));

    invokeCapturePostExitProcessTreeHandoff(host, process);
    childHandle.markExited();

    AppRuntimeStatusSnapshot restartedStatus = waitForRunnerRestarted(host);
    assertNull(restartedStatus.lastExitCode());
    assertEquals(1, restartedStatus.currentRestartAttempt());
    assertEquals(1, restartedStatus.restartCount());
    assertTrue(host.stop(RUNNER_APP_ID));
  }

  @Test
  void restartPolicy_whenDaemonizedChildDisappears_expectUnknownExitRestarts() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_IMMEDIATE_EXIT_SCRIPT,
            Map.of(CHILD_SCRIPT_PATH, DAEMONIZED_RESTART_ON_FAILURE_CHILD_SCRIPT));
    appendOnFailureRestartPolicy(stagedApp, 300);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    host.start(RUNNER_APP_ID);

    Path runCountFile = installation.paths().runDir().resolve("daemonized-restart-count.txt");
    waitForFileContent(runCountFile, "1\n");
    waitForRuntimeState(host, AppRuntimeState.RESTARTING);
    waitForFileContent(runCountFile, "2\n");
    AppRuntimeStatusSnapshot status = waitForRuntimeState(host, AppRuntimeState.RUNNING);
    assertEquals(1, status.currentRestartAttempt());
    assertEquals(1, status.restartCount());

    assertTrue(host.stop(RUNNER_APP_ID));
  }

  @Test
  void restartPolicy_whenDaemonizedChildExitsWithoutPolling_expectObserverRestarts()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_IMMEDIATE_EXIT_SCRIPT,
            Map.of(CHILD_SCRIPT_PATH, DAEMONIZED_RESTART_ON_FAILURE_CHILD_SCRIPT));
    appendOnFailureRestartPolicy(stagedApp, 10);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    host.start(RUNNER_APP_ID);

    Path runCountFile = installation.paths().runDir().resolve("daemonized-restart-count.txt");
    waitForFileContent(runCountFile, "1\n");
    waitForFileContent(runCountFile, "2\n");
    assertTrue(host.stop(RUNNER_APP_ID));
  }

  @Test
  void restartPolicy_whenRestartAttemptExitsDuringStartup_expectAttemptExitRecorded()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp = stageInstalledRunnerApp(RESTART_ATTEMPT_STARTUP_FAILURE_SCRIPT);
    appendOnFailureRestartPolicy(stagedApp, 10);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    host.start(RUNNER_APP_ID);

    Path runCountFile = installation.paths().runDir().resolve("restart-startup-failure-count.txt");
    waitForFileContent(runCountFile, "2\n");
    AppRuntimeStatusSnapshot status = waitForRuntimeState(host, AppRuntimeState.CRASHED);
    assertEquals(9, status.lastExitCode());
    assertEquals(1, status.currentRestartAttempt());
    assertEquals(1, status.restartCount());
  }

  @Test
  void restartPolicy_whenSandboxRejectsRestart_expectRestartMetadataPreserved() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    LocalProcessAppHost host =
        allowUnsignedHost(
            Duration.ofSeconds(1), appEnv, restartRejectingRestrictedProcessProviders());
    Path stagedApp = stageInstalledRunnerApp(RESTART_ON_FAILURE_SCRIPT);
    appendRequiredRestrictedSandbox(stagedApp);
    appendOnFailureRestartPolicy(stagedApp, 10);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    host.start(RUNNER_APP_ID);

    Path runCountFile = installation.paths().runDir().resolve(RESTART_COUNT_FILE_NAME);
    waitForFileContent(runCountFile, "1\n");
    AppRuntimeStatusSnapshot status = waitForRuntimeState(host, AppRuntimeState.CRASHED);
    assertEquals(7, status.lastExitCode());
    assertNotNull(status.lastExitAt());
    assertEquals(1, status.currentRestartAttempt());
    assertEquals(0, status.restartCount());
    assertEquals(AppSandboxSupportLevel.UNSUPPORTED, status.sandboxStatus().supportLevel());
    assertTrue(status.sandboxStatus().required());
    assertFalse(status.sandboxStatus().active());
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertEquals("1\n", Files.readString(runCountFile, StandardCharsets.UTF_8));
  }

  @Test
  void restartPolicy_whenFailuresExceedRollingWindow_expectRestartStormGuardWarning()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHostWithSingleRestartStormLimit();
    Path stagedApp = stageInstalledRunnerApp(RESTART_STORM_SCRIPT);
    appendOnFailureRestartPolicy(stagedApp, 1, 10);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    host.start(RUNNER_APP_ID);

    Path runCountFile = installation.paths().runDir().resolve("restart-storm-count.txt");
    AppRuntimeStatusSnapshot status = waitForRestartStormWarning(host);
    assertEquals(AppRuntimeState.CRASHED, status.state());
    assertTrue(status.currentRestartAttempt() >= 1);
    assertTrue(status.restartCount() >= 1);
    assertTrue(
        Integer.parseInt(Files.readString(runCountFile, StandardCharsets.UTF_8).trim()) >= 2);
  }

  @Test
  void restartBackoffSleepMillis_whenManifestBackoffWouldOverflowNanos_expectMillisValue() {
    long nanosOverflowingBackoffMillis = Long.MAX_VALUE / 1_000_000L + 1L;

    assertEquals(
        nanosOverflowingBackoffMillis,
        LocalProcessAppHost.restartBackoffSleepMillis(
            Duration.ofMillis(nanosOverflowingBackoffMillis)));
    assertEquals(
        Long.MAX_VALUE,
        LocalProcessAppHost.restartBackoffSleepMillis(Duration.ofSeconds(Long.MAX_VALUE)));
  }

  @Test
  void restartPolicy_whenOperatorStopsProcess_expectNoRestart() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp = stageInstalledRunnerApp(RESTART_STOP_SUPPRESSION_SCRIPT);
    appendOnFailureRestartPolicy(stagedApp, 10);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    host.start(RUNNER_APP_ID);
    Path runCountFile = installation.paths().runDir().resolve(RESTART_COUNT_FILE_NAME);
    waitForFileContent(runCountFile, "1\n");
    assertTrue(host.stop(RUNNER_APP_ID));
    LockSupport.parkNanos(Duration.ofMillis(150).toNanos());

    assertEquals("1\n", Files.readString(runCountFile, StandardCharsets.UTF_8));
    assertEquals(AppRuntimeState.STOPPED, host.runtimeStatus(RUNNER_APP_ID).state());
  }

  @Test
  void start_whenInstalledProcessExitsShortlyAfterLaunch_expectNoStaleRunningState()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledRunnerApp(DELAYED_STARTUP_EXIT_SCRIPT));

    try {
      host.start(RUNNER_APP_ID);
    } catch (AppHostException exception) {
      assertTrue(exception.getMessage().contains(STARTUP_EXIT_MESSAGE_PREFIX + RUNNER_APP_ID));
    }

    waitForNotRunning(host);
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  @Test
  void start_whenInstalledExecParentBecomesSymlink_expectFailureBeforeExternalCodeRuns()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    Path externalBin = Files.createDirectories(tempDir.resolve("external-bin"));
    Path externalLaunch = externalBin.resolve(scriptName(appEnv));
    writeStageFile(
        externalLaunch,
        """
        #!/bin/sh
        printf 'escaped' > "$CRYPTAD_APP_RUN_DIR/escaped.txt"
        while :; do
          sleep %s
        done
        """
            .formatted(TEST_LOOP_SLEEP_SECONDS),
        appEnv);
    Path installedBin = installation.paths().installedRoot().resolve("bin");
    Path relocatedInstalledBin = installation.paths().installedRoot().resolve("bin-original");
    Files.move(installedBin, relocatedInstalledBin);
    Files.createSymbolicLink(installedBin, externalBin.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    assertTrue(exception.getMessage().contains("symlinks or reparse points"));
    assertFalse(Files.exists(installation.paths().runDir().resolve("escaped.txt")));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
  }

  @Test
  void start_whenLauncherDaemonizesChildAndExitsImmediately_expectChildManagedAsRunningApp()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost(Duration.ofSeconds(1));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_IMMEDIATE_EXIT_SCRIPT,
            Map.of(CHILD_SCRIPT_PATH, DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      assertEquals(childPid, running.pid());
      RunningAppSnapshot current = waitForRunningApp(host, RUNNER_APP_ID);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertTrue(
          ProcessHandle.of(current.pid())
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertEquals(
          "cannot uninstall a running app: " + RUNNER_APP_ID,
          assertThrows(AppHostException.class, () -> host.uninstall(RUNNER_APP_ID)).getMessage());
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void status_whenLauncherDaemonizesChildAndExitsLater_expectRunningSnapshotPreserved()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost(Duration.ofSeconds(1));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_DELAYED_EXIT_SCRIPT,
            Map.of(CHILD_SCRIPT_PATH, DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    Path wrapperPidFile = installation.paths().runDir().resolve("wrapper.pid");
    long childPid = waitForPidFileValue(childPidFile);
    long wrapperPid = waitForPidFileValue(wrapperPidFile);
    Path wrapperExitedFile = installation.paths().runDir().resolve("wrapper-exited.txt");
    waitForFile(wrapperExitedFile);
    try {
      assertEquals(childPid, running.pid());
      waitForProcessExit(wrapperPid);
      RunningAppSnapshot current = waitForRunningApp(host, RUNNER_APP_ID);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertEquals(childPid, current.pid());
      assertEquals(java.util.List.of(current), host.listRunning());
      assertTrue(
          ProcessHandle.of(current.pid())
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
      ProcessHandle.of(wrapperPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void status_whenLauncherDaemonizesChildAfterStartupCapture_expectChildRetained()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost(Duration.ofSeconds(1));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_POST_CAPTURE_EXIT_SCRIPT,
            Map.of(CHILD_SCRIPT_PATH, DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      RunningAppSnapshot current = waitForRunningPid(host, childPid);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertEquals(childPid, current.pid());
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void status_whenDirectInterpreterLauncherDaemonizesChildAfterStartupCapture_expectChildRetained()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Assumptions.assumeTrue(appEnv.onPath(PYTHON3_COMMAND));
    AppHost host = allowUnsignedHost(Duration.ofSeconds(1));
    Path stagedApp =
        stageInstalledExecutableApp(
            PYTHON_DAEMON_APP_ID,
            POSIX_LAUNCH_PATH,
            POST_CAPTURE_PYTHON_DAEMONIZER,
            Map.of(CHILD_SCRIPT_PATH, DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(PYTHON_DAEMON_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      RunningAppSnapshot current = waitForRunningPid(host, PYTHON_DAEMON_APP_ID, childPid);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertEquals(childPid, current.pid());
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertEquals(java.util.List.of(current), host.listRunning());
      assertTrue(host.stop(PYTHON_DAEMON_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(PYTHON_DAEMON_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void status_whenMacHostLauncherDaemonizesViaIntermediateHelper_expectChildRetained()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost(Duration.ofSeconds(1), new AppEnv(Map.of(), "Mac OS X"));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_VIA_HELPER_SCRIPT,
            Map.of(
                "bin/helper.sh",
                DELAYED_DAEMONIZING_HELPER_SCRIPT,
                CHILD_SCRIPT_PATH,
                DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      RunningAppSnapshot current = waitForRunningPid(host, childPid);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertEquals(childPid, current.pid());
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void status_whenOtherUnixHostLauncherDaemonizesViaIntermediateHelper_expectChildRetained()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost(Duration.ofSeconds(1), new AppEnv(Map.of(), "FreeBSD"));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_VIA_HELPER_SCRIPT,
            Map.of(
                "bin/helper.sh",
                DELAYED_DAEMONIZING_HELPER_SCRIPT,
                CHILD_SCRIPT_PATH,
                DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      RunningAppSnapshot current = waitForRunningPid(host, childPid);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertEquals(childPid, current.pid());
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void recoverTrackedDescendantProcesses_whenWindowsWrapperExited_expectLiveChildRecovered() {
    ProcessHandle wrapper = new ExitedProcessHandle(7100L);
    ProcessHandle helper = new LinkedProcessHandle(7101L, wrapper, false);
    ProcessHandle child = new LinkedProcessHandle(7102L, helper, true);
    ProcessHandle grandchild = new LinkedProcessHandle(7103L, child, true);
    ProcessHandle unrelated = new LinkedProcessHandle(8100L, new ExitedProcessHandle(8099L), true);

    List<ProcessHandle> recovered =
        LocalProcessAppHost.recoverTrackedDescendantProcesses(
            List.of(wrapper, helper), List.of(child, grandchild, unrelated));

    assertEquals(List.of(7102L, 7103L), recovered.stream().map(ProcessHandle::pid).toList());
  }

  @Test
  void
      recoverWindowsBundleProcesses_whenCommandLineReferencesInstalledBundle_expectLiveChildRecovered() {
    InstalledAppPaths paths =
        new AppHostLayout(
                tempDir.resolve("data"), tempDir.resolve(CACHE_DIR_NAME), tempDir.resolve("run"))
            .pathsFor(RUNNER_APP_ID);
    AppManifest manifest =
        new AppManifest(
            1,
            RUNNER_APP_ID,
            displayName(RUNNER_APP_ID),
            APP_VERSION,
            "bin/launch.cmd",
            "/",
            STANDARD_PERMISSIONS,
            4096L,
            1024L);
    Instant startedAt = Instant.parse("2026-04-05T00:00:00Z");
    ProcessHandle wrapper = new ExitedProcessHandle(7200L);
    ProcessHandle staleBundleProcess =
        new InfoProcessHandle(
            7201L,
            null,
            true,
            paths.installedRoot().resolve("bin").resolve(WINDOWS_CHILD_EXECUTABLE).toString(),
            "\"" + paths.installedRoot().resolve("bin").resolve(WINDOWS_CHILD_EXECUTABLE) + "\"",
            startedAt.minusSeconds(5));
    ProcessHandle recoveredChild =
        new InfoProcessHandle(
            7202L,
            null,
            true,
            null,
            "\""
                + paths.installedRoot().resolve("bin").resolve(WINDOWS_CHILD_EXECUTABLE)
                + "\" --serve",
            startedAt.plusMillis(750));

    List<ProcessHandle> recovered =
        LocalProcessAppHost.recoverWindowsBundleProcesses(
            paths,
            manifest,
            startedAt,
            List.of(wrapper),
            List.of(staleBundleProcess, recoveredChild));

    assertEquals(List.of(7202L), recovered.stream().map(ProcessHandle::pid).toList());
  }

  @Test
  void parseTokenTrackedProcesses_whenReaderFails_expectCheckedIoException() {
    Process process =
        new FailingInputProcess(
            (ProcessHandle.current().pid()
                    + " CRYPTAD_APP_TOKEN="
                    + DEFAULT_TOKEN
                    + " CRYPTAD_APP_ID="
                    + RUNNER_APP_ID
                    + "\n")
                .getBytes(StandardCharsets.UTF_8));

    IOException exception =
        assertThrows(IOException.class, () -> invokeParseRunnerTokenTrackedProcesses(process));

    assertEquals("simulated ps stream failure", exception.getMessage());
  }

  @Test
  void mergeTokenTrackedProcesses_whenProcReturnsEmptyOnUnix_expectPsFallback() {
    ProcessHandle psRecovered = new LinkedProcessHandle(7205L, null, true);

    List<ProcessHandle> recovered =
        LocalProcessAppHost.mergeTokenTrackedProcesses(
            List.of(), List.of(psRecovered), new AppEnv(Map.of(), LINUX_OS_NAME));

    assertEquals(List.of(7205L), recovered.stream().map(ProcessHandle::pid).toList());
  }

  @Test
  void recoverWindowsBundleProcesses_whenProcessStartsLongAfterLaunch_expectIgnored() {
    InstalledAppPaths paths =
        new AppHostLayout(
                tempDir.resolve("data"), tempDir.resolve(CACHE_DIR_NAME), tempDir.resolve("run"))
            .pathsFor(RUNNER_APP_ID);
    AppManifest manifest =
        new AppManifest(
            1,
            RUNNER_APP_ID,
            displayName(RUNNER_APP_ID),
            APP_VERSION,
            "bin/launch.cmd",
            "/",
            STANDARD_PERMISSIONS,
            4096L,
            1024L);
    Instant startedAt = Instant.parse("2026-04-05T00:00:00Z");
    ProcessHandle unrelatedLaterProcess =
        new InfoProcessHandle(
            7204L,
            null,
            true,
            null,
            "\""
                + paths.installedRoot().resolve("bin").resolve(WINDOWS_CHILD_EXECUTABLE)
                + "\" --serve",
            startedAt.plusSeconds(30));

    List<ProcessHandle> recovered =
        LocalProcessAppHost.recoverWindowsBundleProcesses(
            paths,
            manifest,
            startedAt,
            List.of(new ExitedProcessHandle(7200L)),
            List.of(unrelatedLaterProcess));

    assertEquals(List.of(), recovered);
  }

  @Test
  void status_whenDirectLauncherSpawnsChildAfterStartupGrace_expectChildRetained()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost(Duration.ofSeconds(1));
    Path stagedApp =
        stageInstalledExecutableApp(
            LATE_CHILD_APP_ID,
            POSIX_LAUNCH_PATH,
            LATE_CHILD_DIRECT_EXECUTABLE,
            Map.of(CHILD_SCRIPT_PATH, DETACHED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(LATE_CHILD_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    Path wrapperExitedFile = installation.paths().runDir().resolve("wrapper-exited.txt");
    waitForFile(wrapperExitedFile);
    try {
      RunningAppSnapshot current = waitForRunningApp(host, LATE_CHILD_APP_ID);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(host.stop(LATE_CHILD_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(LATE_CHILD_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void stop_whenProcessDoesNotExit_expectRunningStatePreserved()
      throws ReflectiveOperationException {
    LocalProcessAppHost host = allowUnsignedHost(Duration.ofMillis(10));
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);
    injectRunningProcess(host, RUNNER_APP_ID, snapshot, new NonStoppingProcess(snapshot.pid()));

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.stop(RUNNER_APP_ID));

    assertEquals("timed out stopping app: " + RUNNER_APP_ID, exception.getMessage());
    assertEquals(snapshot, host.status(RUNNER_APP_ID).orElseThrow());
    assertEquals(java.util.List.of(snapshot), host.listRunning());
    assertEquals(
        "cannot uninstall a running app: " + RUNNER_APP_ID,
        assertThrows(AppHostException.class, () -> host.uninstall(RUNNER_APP_ID)).getMessage());
    assertEquals(
        "app is already running: " + RUNNER_APP_ID,
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID)).getMessage());
  }

  @Test
  void stop_whenProcessExitsBetweenRefreshAndTracking_expectCleanSuccess()
      throws IOException, ReflectiveOperationException {
    LocalProcessAppHost host = allowUnsignedHost();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);
    injectRunningProcess(
        host,
        RUNNER_APP_ID,
        snapshot,
        new FadingProcess(snapshot.pid(), 2),
        CompletableFuture.completedFuture(null));

    assertTrue(host.stop(RUNNER_APP_ID));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  @Test
  void status_whenLiveProcessHandleOmitsOptionalMetadata_expectSnapshotRetained()
      throws ReflectiveOperationException {
    LocalProcessAppHost host = allowUnsignedHost();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);
    injectRunningProcess(host, RUNNER_APP_ID, snapshot, new NonStoppingProcess(snapshot.pid()));

    assertEquals(snapshot, host.status(RUNNER_APP_ID).orElseThrow());
    assertEquals(java.util.List.of(snapshot), host.listRunning());
  }

  @Test
  void stop_whenWrapperScriptOwnsChildProcess_expectEntireProcessTreeTerminated()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost(Duration.ofSeconds(2));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID, WRAPPER_SCRIPT, Map.of(CHILD_SCRIPT_PATH, CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
      assertTrue(host.listRunning().isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void stop_whenRecoveredLateChildExitsWithinStopTimeout_expectCleanSuccess()
      throws IOException, ReflectiveOperationException {
    long recoveredChildPid = 84L;
    LocalProcessAppHost host = allowUnsignedHost(Duration.ofMillis(200));
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);
    injectRunningProcess(
        host,
        RUNNER_APP_ID,
        snapshot,
        new LateRecoveredChildProcess(snapshot.pid(), recoveredChildPid, 8),
        CompletableFuture.completedFuture(null));

    assertTrue(host.stop(RUNNER_APP_ID));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  @Test
  void stop_whenShutdownSpawnsReplacementChild_expectFailureAndRunningStatePreserved()
      throws ReflectiveOperationException {
    String appId = "shutdown-respawn-app";
    long replacementChildPid = 84L;
    LocalProcessAppHost host = allowUnsignedHost(Duration.ofMillis(200));
    RunningAppSnapshot snapshot = runningSnapshot(appId);
    injectRunningProcess(
        host, appId, snapshot, new LateChildSpawningProcess(snapshot.pid(), replacementChildPid));

    AppHostException exception = assertThrows(AppHostException.class, () -> host.stop(appId));

    assertEquals("timed out stopping app: " + appId, exception.getMessage());
    RunningAppSnapshot current = host.status(appId).orElseThrow();
    assertEquals(appId, current.appId());
    assertEquals(replacementChildPid, current.pid());
  }

  @Test
  void launchCommand_whenWindowsBatchScript_expectQuotedCmdWrapper() throws IOException {
    AppEnv windowsAppEnv = new AppEnv(Map.of(), WINDOWS_11);
    Path batchScript = Path.of("C:/Users/Alice & Bob/Cryptad Apps^(1)/runner/bin/launch.cmd");
    Path nativeExecutable = Path.of("C:/apps/runner/bin/runner.exe");

    List<String> batchCommand = LocalProcessAppHost.launchCommand(batchScript, windowsAppEnv);

    assertEquals(4, batchCommand.size());
    assertTrue(batchCommand.get(0).toLowerCase(java.util.Locale.ROOT).endsWith("cmd.exe"));
    assertEquals("/d", batchCommand.get(1));
    assertEquals("/c", batchCommand.get(2));
    assertEquals("\"" + batchScript + "\"", batchCommand.get(3));
    assertEquals(
        java.util.List.of(nativeExecutable.toString()),
        LocalProcessAppHost.launchCommand(nativeExecutable, windowsAppEnv));
  }

  @Test
  void launchCommand_whenShebangUsesEnvSplitString_expectInterpreterArgumentPreserved()
      throws IOException {
    AppEnv appEnv = new AppEnv(Map.of(), LINUX_OS_NAME);
    Path script = tempDir.resolve("env-shebang.sh");
    Files.writeString(
        script,
        """
        #!/usr/bin/env -S bash -euo pipefail
        exit 0
        """,
        StandardCharsets.UTF_8);
    assertTrue(script.toFile().setExecutable(true, false));

    List<String> command = LocalProcessAppHost.launchCommand(script, appEnv);

    assertEquals(SYSTEM_ENV_COMMAND, command.get(0));
    assertEquals("-S bash -euo pipefail", command.get(1));
    assertEquals("-c", command.get(2));
    assertEquals(script.toString(), command.get(4));
  }

  @Test
  void installFromDirectory_whenShebangInterpreterIsFilesystemRoot_expectFailure()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp =
        stageInstalledExecutableApp(
            "invalid-shebang-app",
            POSIX_START_PATH,
            """
            #!/
            exit 0
            """,
            Map.of());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertEquals("invalid shebang interpreter: /", exception.getMessage());
  }

  @Test
  void launchCommand_whenPythonShebangUsesShSuffix_expectInterpreterLaunch() throws IOException {
    AppEnv appEnv = new AppEnv(Map.of(), LINUX_OS_NAME);
    Path script = tempDir.resolve("python-launch.sh");
    Files.writeString(
        script,
        """
        #!/usr/bin/env %s
        print("ok")
        """
            .formatted(PYTHON3_COMMAND),
        StandardCharsets.UTF_8);

    List<String> command = LocalProcessAppHost.launchCommand(script, appEnv);

    assertEquals(SYSTEM_ENV_COMMAND, command.getFirst());
    assertEquals(PYTHON3_COMMAND, command.get(1));
    assertEquals(script.toString(), command.get(2));
  }

  @Test
  void installFromDirectory_whenInterpreterManagedLauncherContainsNonUtf8Body_expectSuccess()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Assumptions.assumeTrue(appEnv.onPath(PYTHON3_COMMAND));
    AppHost host = allowUnsignedHost();
    Path stagedApp =
        stageInstalledExecutableApp(
            "non-utf8-launcher-app",
            POSIX_START_PATH,
            """
            #!/usr/bin/env %s
            pass
            """
                .formatted(PYTHON3_COMMAND),
            Map.of(),
            false);
    Path script = stagedApp.resolve(POSIX_START_PATH);
    try (OutputStream output = Files.newOutputStream(script)) {
      output.write(
          ("#!/usr/bin/env " + PYTHON3_COMMAND + "\n").getBytes(StandardCharsets.US_ASCII));
      output.write(new byte[] {(byte) 0xC3, (byte) 0x28, (byte) '\n'});
    }

    List<String> command = LocalProcessAppHost.launchCommand(script, appEnv);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    assertEquals(SYSTEM_ENV_COMMAND, command.getFirst());
    assertEquals(PYTHON3_COMMAND, command.get(1));
    assertEquals(script.toString(), command.get(2));
    assertEquals("non-utf8-launcher-app", installation.appId());
  }

  @Test
  void start_whenPosixShellScriptRequiresShebangAndZeroArguments_expectSuccessfulLaunch()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Assumptions.assumeTrue(appEnv.onPath("bash"));
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation =
        host.installFromDirectory(
            stageInstalledRunnerApp(
                """
                #!/usr/bin/env bash
                set -euo pipefail
                [[ $# -eq 0 ]]
                letters=(alpha beta)
                printf '%%s' "${letters[0]}" > "$CRYPTAD_APP_RUN_DIR/shebang-ok.txt"
                while :; do
                  sleep %s
                done
                """
                    .formatted(TEST_LOOP_SLEEP_SECONDS)));

    host.start(RUNNER_APP_ID);

    Path confirmationFile = installation.paths().runDir().resolve("shebang-ok.txt");
    waitForFile(confirmationFile);
    assertEquals("alpha", Files.readString(confirmationFile, StandardCharsets.UTF_8));
    assertTrue(host.stop(RUNNER_APP_ID));
  }

  @Test
  void start_whenExtensionlessShebangLauncherLacksExecuteBit_expectSuccessfulLaunch()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation =
        host.installFromDirectory(
            stageInstalledExecutableApp(
                SHELL_NOEXEC_APP_ID,
                POSIX_START_PATH,
                """
                #!/bin/sh
                set -eu
                printf '%%s' "ok" > "$CRYPTAD_APP_RUN_DIR/noexec-ok.txt"
                while :; do
                  sleep %s
                done
                """
                    .formatted(TEST_LOOP_SLEEP_SECONDS),
                Map.of(),
                false));

    host.start(SHELL_NOEXEC_APP_ID);

    Path confirmationFile = installation.paths().runDir().resolve("noexec-ok.txt");
    waitForFile(confirmationFile);
    assertEquals("ok", Files.readString(confirmationFile, StandardCharsets.UTF_8));
    assertTrue(host.stop(SHELL_NOEXEC_APP_ID));
  }

  @Test
  void start_whenLauncherWaitsForStandardInputEof_expectInitializationContinues()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost(Duration.ofSeconds(2));
    InstalledAppSnapshot installation =
        host.installFromDirectory(stageInstalledRunnerApp(STDIN_EOF_SCRIPT));

    host.start(RUNNER_APP_ID);

    Path confirmationFile = installation.paths().runDir().resolve("stdin-closed.txt");
    waitForFile(confirmationFile);
    assertEquals("closed\n", Files.readString(confirmationFile, StandardCharsets.UTF_8));
    assertTrue(host.stop(RUNNER_APP_ID));
  }

  @Test
  void start_whenShellLauncherExitsCleanlyWithoutChild_expectFailureAfterSingleExecution()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation =
        host.installFromDirectory(stageInstalledRunnerApp(SINGLE_RUN_EXIT_SCRIPT));

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    Path runCountFile = installation.paths().runDir().resolve("run-count.txt");
    waitForFile(runCountFile);
    assertEquals("1\n", Files.readString(runCountFile, StandardCharsets.UTF_8));
    assertTrue(exception.getMessage().contains(STARTUP_EXIT_MESSAGE_PREFIX + RUNNER_APP_ID));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  @Test
  void populateEnvironment_whenHostEnvironmentContainsSecrets_expectSanitizedChildEnvironment() {
    Map<String, String> environment = new HashMap<>();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);

    for (String name :
        List.of(
            "HOME",
            "USER",
            "LOGNAME",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "SSH_AUTH_SOCK",
            "SSH_AGENT_PID",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "SECRET",
            "TOKEN",
            "PASSWORD",
            "PRIVATE_KEY",
            "CRYPTAD_NODE_DATASTORE_DIR",
            "CRYPTAD_APPHOST_BWRAP",
            "PATH")) {
      environment.put(name, "secret-" + name);
    }

    LocalProcessAppHost.populateEnvironment(
        environment,
        snapshot.manifest(),
        snapshot.paths(),
        DEFAULT_TOKEN,
        new AppEnv(Map.of(), LINUX_OS_NAME));

    assertEquals(
        Set.of(
            "PATH",
            "CRYPTAD_APP_ID",
            "CRYPTAD_APP_NAME",
            "CRYPTAD_APP_VERSION",
            "CRYPTAD_APP_DATA_DIR",
            "CRYPTAD_APP_CACHE_DIR",
            "CRYPTAD_APP_RUN_DIR",
            APP_TOKEN_ENV_NAME,
            "CRYPTAD_APP_PERMISSIONS",
            "CRYPTAD_APP_UI_MODE",
            "CRYPTAD_APP_UI_ENTRY"),
        environment.keySet());
    assertEquals(
        "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:"
            + "/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin",
        environment.get("PATH"));
    assertEquals(DEFAULT_TOKEN, environment.get(APP_TOKEN_ENV_NAME));
    assertEquals(RUNNER_APP_ID, environment.get("CRYPTAD_APP_ID"));
    assertEquals("shell-panel", environment.get("CRYPTAD_APP_UI_MODE"));
  }

  @Test
  void populateEnvironment_whenMacBaseEnvironment_expectPackageManagerPrefixesPresent() {
    Map<String, String> environment = new HashMap<>();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);

    LocalProcessAppHost.populateEnvironment(
        environment,
        snapshot.manifest(),
        snapshot.paths(),
        DEFAULT_TOKEN,
        new AppEnv(Map.of(), "Mac OS X"));

    assertEquals(
        "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:"
            + "/opt/homebrew/bin:/opt/homebrew/sbin:/opt/local/bin:/opt/local/sbin",
        environment.get("PATH"));
  }

  @Test
  void populateEnvironment_whenWindowsBaseEnvironment_expectPowerShellDirectoryPresent() {
    Map<String, String> environment = new HashMap<>();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);

    LocalProcessAppHost.populateEnvironment(
        environment,
        snapshot.manifest(),
        snapshot.paths(),
        DEFAULT_TOKEN,
        new AppEnv(Map.of(), WINDOWS_11));

    List<String> pathEntries = List.of(environment.get("PATH").replace('\\', '/').split(";"));
    assertTrue(pathEntries.stream().anyMatch(entry -> entry.endsWith("/System32")));
    assertTrue(
        pathEntries.stream().anyMatch(entry -> entry.endsWith("/System32/WindowsPowerShell/v1.0")));
  }

  @Test
  void ownerOnlyFilePermissions_whenPosixViewAvailable_expectOwnerOnlyModes() throws IOException {
    Path directory = Files.createDirectories(tempDir.resolve("owner-only-dir"));
    Path file =
        Files.writeString(directory.resolve(PROCESS_LOG_FILE_NAME), "log", StandardCharsets.UTF_8);
    Assumptions.assumeTrue(
        Files.getFileAttributeView(directory, PosixFileAttributeView.class) != null);

    assertTrue(OwnerOnlyFilePermissions.hardenDirectory(directory));
    assertTrue(OwnerOnlyFilePermissions.hardenSensitiveFile(file));

    assertEquals(
        Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE),
        Files.getPosixFilePermissions(directory));
    assertEquals(
        Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
        Files.getPosixFilePermissions(file));
  }

  @Test
  void ownerOnlyFilePermissions_whenPathIsSymlink_expectTargetPermissionsUnchanged()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Path target =
        Files.writeString(tempDir.resolve("symlink-target.log"), "log", StandardCharsets.UTF_8);
    Assumptions.assumeTrue(
        Files.getFileAttributeView(target, PosixFileAttributeView.class) != null);
    Set<PosixFilePermission> targetPermissions =
        Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.GROUP_READ,
            PosixFilePermission.OTHERS_READ);
    Files.setPosixFilePermissions(target, targetPermissions);
    Path link = tempDir.resolve("symlink-process.log");
    try {
      Files.createSymbolicLink(link, target);
    } catch (IOException | UnsupportedOperationException exception) {
      Assumptions.assumeTrue(false, "symbolic links unavailable: " + exception.getMessage());
    }

    try {
      OwnerOnlyFilePermissions.hardenSensitiveFile(link);
    } catch (IOException _) {
      // Some POSIX providers expose a no-follow symlink view but do not support chmod on symlinks.
    }

    assertEquals(targetPermissions, Files.getPosixFilePermissions(target));
  }

  @Test
  void ownerOnlyFilePermissions_whenPosixViewUnavailable_expectFallbackWithoutFailure()
      throws IOException {
    Path zipFile = tempDir.resolve("non-posix.zip");
    URI zipUri = URI.create("jar:" + zipFile.toUri());
    try (FileSystem zipFs = FileSystems.newFileSystem(zipUri, Map.of("create", "true"))) {
      Path directory = zipFs.getPath("/state");
      Files.createDirectory(directory);
      Path file =
          Files.writeString(
              directory.resolve(PROCESS_LOG_FILE_NAME), "log", StandardCharsets.UTF_8);

      assertFalse(OwnerOnlyFilePermissions.hardenDirectory(directory));
      assertFalse(OwnerOnlyFilePermissions.hardenSensitiveFile(file));
    }
  }

  @Test
  void installFromDirectory_whenStagingContainsNamedPipe_expectFailureWithoutHanging()
      throws Exception {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Assumptions.assumeTrue(appEnv.onPath(MKFIFO_COMMAND));
    AppHost host = allowUnsignedHost();
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    Path namedPipe = stagedApp.resolve("blocked.pipe");

    Process mkfifo =
        new ProcessBuilder(resolveTrustedMkfifoCommand(), namedPipe.toString()).start();
    assertEquals(0, waitForExit(mkfifo));

    AppHostException exception = installExpectingAppHostException(host, stagedApp);

    assertTrue(
        exception.getMessage().contains("staging directory must contain only regular files"));
  }

  @Test
  void installFromDirectory_whenStaticUiEntryIsMissing_expectFailure() throws Exception {
    AppEnv appEnv = new AppEnv();
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    Files.writeString(
        stagedApp.resolve(MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/%s
        app.ui.mode=static
        app.ui.entry=static/index.html
        app.permissions=%s
        quota.data.bytes=4096
        quota.cache.bytes=1024
        """
            .formatted(
                SAMPLE_APP_ID,
                displayName(SAMPLE_APP_ID),
                APP_VERSION,
                scriptName(appEnv),
                STANDARD_PERMISSIONS_TEXT),
        StandardCharsets.UTF_8);
    AppHost host = allowUnsignedHost();

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertEquals(
        "app.ui.entry does not resolve to a file in copied bundle: static/index.html",
        exception.getMessage());
  }

  @Test
  void installFromDirectory_whenManifestIsSymlink_expectFailureBeforeParsingExternalContent()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp =
        Files.createDirectories(tempDir.resolve(STAGE_DIR_NAME).resolve("manifest-symlink"));
    Path externalManifest = tempDir.resolve("outside-manifest.properties");
    String externalContent = "outside-secret-data";
    Files.writeString(externalManifest, externalContent, StandardCharsets.UTF_8);
    Files.createSymbolicLink(
        stagedApp.resolve(MANIFEST_FILE_NAME), externalManifest.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("symlink"));
    assertFalse(exception.getMessage().contains(externalContent));
  }

  @Test
  void installFromDirectory_whenStagingRootIsSymlink_expectFailure() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    Path linkedRoot = tempDir.resolve("linked-stage-root");
    Files.createSymbolicLink(linkedRoot, stagedApp.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(linkedRoot));

    assertTrue(exception.getMessage().contains("stagedAppDirectory must not be a symlink"));
  }

  @Test
  void installFromDirectory_whenStagingRootHasAliasedAncestor_expectSuccess() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path realStagingParent = Files.createDirectories(tempDir.resolve("real-staging-parent"));
    Path aliasedParent = tempDir.resolve("aliased-staging-parent");
    Files.createSymbolicLink(aliasedParent, realStagingParent.toAbsolutePath());
    Path stagedApp =
        stageInstalledAppAt(
            aliasedParent.resolve(SAMPLE_APP_ID), SAMPLE_APP_ID, scriptContent(appEnv), Map.of());

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    assertEquals(SAMPLE_APP_ID, installation.appId());
    assertTrue(Files.isRegularFile(installation.paths().manifestFile()));
  }

  @Test
  void start_whenMutableRunDirectoryBecomesSymlink_expectFailureBeforeWritingOutsideLayout()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    Path externalRun = Files.createDirectories(tempDir.resolve("external-run"));
    Files.delete(installation.paths().runDir());
    Files.createSymbolicLink(installation.paths().runDir(), externalRun.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    assertTrue(exception.getMessage().contains("runDir must not be a symlink"));
    assertFalse(Files.exists(externalRun.resolve(PROCESS_LOG_FILE_NAME)));
  }

  @Test
  void start_whenMutableRunAncestorBecomesSymlink_expectFailureBeforeWritingOutsideLayout()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    Path runAppsDir = tempDir.resolve("run").resolve("apps");
    Path externalRunAppsDir = tempDir.resolve("external-run-apps");
    Files.move(runAppsDir, externalRunAppsDir);
    Files.createSymbolicLink(runAppsDir, externalRunAppsDir.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    assertTrue(exception.getMessage().contains("runDir must not be a symlink"));
    assertFalse(
        Files.exists(externalRunAppsDir.resolve(RUNNER_APP_ID).resolve(PROCESS_LOG_FILE_NAME)));
  }

  @Test
  void start_whenRequiredWasmSandboxUnsupported_expectClearFailureAndUnsupportedStatus()
      throws Exception {
    LocalProcessAppHost host = allowUnsignedHost();
    Path stagedApp = stageInstalledApp(RUNNER_APP_ID);
    Files.writeString(
        stagedApp.resolve(MANIFEST_FILE_NAME),
        """
        sandbox.mode=wasm-preview
        sandbox.required=true
        """,
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);
    host.installFromDirectory(stagedApp);

    AppSandboxException exception =
        assertThrows(AppSandboxException.class, () -> host.start(RUNNER_APP_ID));

    assertEquals("unsupported_sandbox", exception.errorCode());
    assertTrue(exception.getMessage().contains("wasm-preview"));
    assertFalse(exception.getMessage().contains(APP_TOKEN_ENV_NAME));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
    assertEquals(AppSandboxSupportLevel.UNSUPPORTED, status.sandboxStatus().supportLevel());
    assertTrue(status.sandboxStatus().required());
  }

  @Test
  void runtimeStatus_whenProviderDisabledOptionalRestrictedProcessBeforeStart_expectUnsupported()
      throws Exception {
    AppEnv appEnv = new AppEnv(Map.of("PATH", "/usr/bin"), LINUX_OS_NAME);
    LocalProcessAppHost host =
        allowUnsignedHost(
            Duration.ofSeconds(1),
            appEnv,
            AppSandboxProviders.fromHostConfiguration(
                appEnv, Map.of(AppSandboxProviders.SANDBOX_PROVIDER_ENV, "none")));
    Path stagedApp = stageInstalledApp(RUNNER_APP_ID);
    appendOptionalRestrictedSandbox(stagedApp);
    host.installFromDirectory(stagedApp);

    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);

    assertFalse(status.running());
    assertEquals(AppSandboxMode.RESTRICTED_PROCESS, status.sandboxStatus().mode());
    assertFalse(status.sandboxStatus().required());
    assertEquals(AppSandboxSupportLevel.UNSUPPORTED, status.sandboxStatus().supportLevel());
    assertEquals("unsupported", status.sandboxStatus().providerName());
    assertFalse(status.sandboxStatus().active());
  }

  @Test
  void runtimeStatus_whenEnforcedProviderSelectedBeforeStart_expectProviderAwareInactiveStatus()
      throws Exception {
    AppEnv appEnv = new AppEnv();
    LocalProcessAppHost host =
        allowUnsignedHost(Duration.ofSeconds(1), appEnv, enforcedRestrictedProcessProviders());
    Path stagedApp = stageInstalledApp(RUNNER_APP_ID);
    appendRequiredRestrictedSandbox(stagedApp);
    host.installFromDirectory(stagedApp);

    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);

    assertFalse(status.running());
    assertEquals(AppSandboxSupportLevel.ENFORCED, status.sandboxStatus().supportLevel());
    assertEquals(BUBBLEWRAP_PROVIDER_NAME, status.sandboxStatus().providerName());
    assertFalse(status.sandboxStatus().active());
    assertTrue(status.sandboxStatus().reason().contains("will be used on start"));
    assertFalse(status.sandboxStatus().toString().contains(DEFAULT_TOKEN));
    assertFalse(status.sandboxStatus().toString().contains(tempDir.toString()));
  }

  @Test
  void start_whenRequiredRestrictedProcessProviderEnforced_expectStatusRetainedAfterStop()
      throws Exception {
    AppEnv appEnv = new AppEnv();
    LocalProcessAppHost host =
        allowUnsignedHost(Duration.ofSeconds(1), appEnv, enforcedRestrictedProcessProviders());
    Path stagedApp = stageInstalledApp(RUNNER_APP_ID);
    appendRequiredRestrictedSandbox(stagedApp);
    host.installFromDirectory(stagedApp);

    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    assertEquals(AppSandboxSupportLevel.ENFORCED, running.sandboxStatus().supportLevel());
    assertEquals(BUBBLEWRAP_PROVIDER_NAME, running.sandboxStatus().providerName());
    assertTrue(host.stop(RUNNER_APP_ID));
    AppRuntimeStatusSnapshot stopped = host.runtimeStatus(RUNNER_APP_ID);
    assertFalse(stopped.running());
    assertEquals(AppSandboxSupportLevel.ENFORCED, stopped.sandboxStatus().supportLevel());
    assertEquals(BUBBLEWRAP_PROVIDER_NAME, stopped.sandboxStatus().providerName());
    assertFalse(stopped.sandboxStatus().active());
    assertTrue(stopped.sandboxStatus().reason().contains("not running"));
    assertFalse(stopped.sandboxStatus().reason().contains("sandbox active"));
    assertTrue(
        stopped
            .sandboxStatus()
            .warnings()
            .contains("Sandbox restrictions are not active because the app is not running"));
    assertFalse(stopped.sandboxStatus().toString().contains(DEFAULT_TOKEN));
    assertFalse(stopped.sandboxStatus().toString().contains(tempDir.toString()));
  }

  @Test
  void runtimeStatus_whenEnforcedLaunchCrashes_expectSandboxStatusInactive() throws Exception {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    LocalProcessAppHost host =
        allowUnsignedHost(Duration.ofSeconds(1), appEnv, enforcedRestrictedProcessProviders());
    Path stagedApp =
        stageInstalledRunnerApp(
            """
            #!/bin/sh
            sleep 0.500
            exit 7
            """);
    appendRequiredRestrictedSandbox(stagedApp);
    host.installFromDirectory(stagedApp);

    host.start(RUNNER_APP_ID);

    AppRuntimeStatusSnapshot crashed = waitForCrashedInactiveSandboxStatus(host);
    assertFalse(crashed.running());
    assertEquals(AppSandboxSupportLevel.ENFORCED, crashed.sandboxStatus().supportLevel());
    assertEquals(BUBBLEWRAP_PROVIDER_NAME, crashed.sandboxStatus().providerName());
    assertFalse(crashed.sandboxStatus().active());
    assertTrue(crashed.sandboxStatus().reason().contains("not running"));
  }

  @Test
  void runtimeStatus_whenStoppedAppUpdatedToNoSandbox_expectSandboxStatusRefreshes()
      throws Exception {
    AppEnv appEnv = new AppEnv();
    LocalProcessAppHost host =
        allowUnsignedHost(Duration.ofSeconds(1), appEnv, enforcedRestrictedProcessProviders());
    Path stagedApp = stageInstalledApp(RUNNER_APP_ID);
    appendRequiredRestrictedSandbox(stagedApp);
    host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);
    assertEquals(AppSandboxSupportLevel.ENFORCED, running.sandboxStatus().supportLevel());
    assertTrue(host.stop(RUNNER_APP_ID));
    Path updatedStage =
        stageInstalledAppAt(
            tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve("sandbox-policy").resolve(RUNNER_APP_ID),
            RUNNER_APP_ID,
            UPDATED_APP_VERSION,
            scriptContent(appEnv),
            Map.of());

    InstalledAppSnapshot updated = host.updateFromDirectory(RUNNER_APP_ID, updatedStage);

    assertEquals(AppSandboxMode.NONE, updated.manifest().sandboxPolicy().mode());
    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
    assertEquals(AppSandboxMode.NONE, status.sandboxStatus().mode());
    assertFalse(status.sandboxStatus().required());
    assertEquals(AppSandboxSupportLevel.NONE, status.sandboxStatus().supportLevel());
    assertEquals("no-sandbox", status.sandboxStatus().providerName());
  }

  @Test
  void start_whenRequiredRestrictedProcessOnlyBestEffort_expectFailureBeforeProcessStart()
      throws Exception {
    AppEnv appEnv = new AppEnv(Map.of("PATH", ""), LINUX_OS_NAME);
    LocalProcessAppHost host =
        allowUnsignedHost(
            Duration.ofSeconds(1),
            appEnv,
            AppSandboxProviders.fromHostConfiguration(
                appEnv, Map.of(AppSandboxProviders.SANDBOX_PROVIDER_ENV, "best-effort")));
    Path stagedApp = stageInstalledApp(RUNNER_APP_ID);
    appendRequiredRestrictedSandbox(stagedApp);
    host.installFromDirectory(stagedApp);

    AppSandboxException exception =
        assertThrows(AppSandboxException.class, () -> host.start(RUNNER_APP_ID));

    assertEquals("unsupported_sandbox", exception.errorCode());
    assertFalse(exception.getMessage().contains(APP_TOKEN_ENV_NAME));
    assertFalse(exception.getMessage().contains(tempDir.toString()));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertFalse(
        Files.exists(
            tempDir
                .resolve("run")
                .resolve("apps")
                .resolve(RUNNER_APP_ID)
                .resolve("captured-env.txt")));
    AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
    assertEquals(AppSandboxSupportLevel.UNSUPPORTED, status.sandboxStatus().supportLevel());
    assertTrue(status.sandboxStatus().required());
  }

  @Test
  void installFromDirectory_whenStagingRootOverlapsInstalledTree_expectCleanFailure()
      throws IOException {
    AppHost host = allowUnsignedHost();
    Path stagedApp =
        stageInstalledAppAt(
            tempDir.resolve("data"), SAMPLE_APP_ID, scriptContent(new AppEnv()), Map.of());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("must not overlap the installed app tree"));
    assertFalse(Files.exists(tempDir.resolve("data").resolve("apps").resolve(INSTALLED_DIR_NAME)));
  }

  @Test
  void installFromDirectory_whenStagingRootCollidesWithRunDir_expectCleanFailure()
      throws IOException {
    AppHost host = allowUnsignedHost();
    Path stagedApp =
        stageInstalledAppAt(
            tempDir.resolve("run").resolve("apps").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            scriptContent(new AppEnv()),
            Map.of());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("must not overlap runDir"));
    assertTrue(Files.isRegularFile(stagedApp.resolve(MANIFEST_FILE_NAME)));
    assertTrue(Files.isRegularFile(stagedApp.resolve(CONTENT_FILE_NAME)));
  }

  @Test
  void installFromDirectory_whenWindowsJunctionEscapesStagingRoot_expectFailure() throws Exception {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeTrue(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    Path externalRoot = Files.createDirectories(tempDir.resolve("outside-root"));
    Path junction = stagedApp.resolve("outside-junction");

    Process mklink =
        new ProcessBuilder(
                windowsCommandInterpreter(),
                "/c",
                "mklink",
                "/J",
                junction.toString(),
                externalRoot.toString())
            .start();
    assertEquals(0, waitForExit(mklink));

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("links or reparse points"));
  }

  @Test
  void uninstall_whenWindowsJunctionExistsUnderAppData_expectTargetPreserved() throws Exception {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeTrue(appEnv.isWindows());
    AppHost host = allowUnsignedHost();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Path externalRoot = Files.createDirectories(tempDir.resolve("outside-uninstall-root"));
    Path externalFile = externalRoot.resolve("outside.txt");
    Files.writeString(externalFile, "preserve", StandardCharsets.UTF_8);
    Path junction = installation.paths().dataDir().resolve("outside-junction");

    Process mklink =
        new ProcessBuilder(
                windowsCommandInterpreter(),
                "/c",
                "mklink",
                "/J",
                junction.toString(),
                externalRoot.toString())
            .start();
    assertEquals(0, waitForExit(mklink));

    host.uninstall(SAMPLE_APP_ID);

    assertTrue(Files.exists(externalFile));
    assertFalse(Files.exists(installation.paths().installedRoot()));
    assertFalse(Files.exists(installation.paths().dataDir()));
    assertFalse(Files.exists(installation.paths().cacheDir()));
    assertFalse(Files.exists(installation.paths().runDir()));
  }

  @Test
  void preserveRunningState_whenTrackedProcessAlreadyExited_expectEntryRemovedWithoutFailure()
      throws ReflectiveOperationException {
    LocalProcessAppHost host = allowUnsignedHost();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);
    injectRunningProcess(host, RUNNER_APP_ID, snapshot, new ExitedProcess(snapshot.pid()));

    Object runningProcess = runnerProcessEntry(host);
    boolean preserved = invokePreserveRunnerState(host, runningProcess);

    assertFalse(preserved);
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  @Test
  void preserveRunningState_whenTrackedProcessExitsDuringRefresh_expectEntryRemovedWithoutFailure()
      throws ReflectiveOperationException {
    LocalProcessAppHost host = allowUnsignedHost();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);
    injectRunningProcess(host, RUNNER_APP_ID, snapshot, new FadingProcess(snapshot.pid(), 1));

    Object runningProcess = runnerProcessEntry(host);
    boolean preserved = invokePreserveRunnerState(host, runningProcess);

    assertFalse(preserved);
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  private LocalProcessAppHost allowUnsignedHost() {
    return allowUnsignedHost(Duration.ofSeconds(1));
  }

  private LocalProcessAppHost allowUnsignedHost(Duration stopTimeout) {
    return allowUnsignedHost(stopTimeout, new AppEnv());
  }

  private LocalProcessAppHost allowUnsignedHost(Duration stopTimeout, AppEnv appEnv) {
    return new LocalProcessAppHost(
        layout(),
        stopTimeout,
        new java.security.SecureRandom(),
        appEnv,
        TEST_TIMING,
        AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly());
  }

  private static LocalProcessAppHost developmentHost(AppHostLayout layout) {
    return new LocalProcessAppHost(
        layout, AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly());
  }

  private static InstalledAppOrigin origin(String version) {
    return origin(version, null);
  }

  private static InstalledAppOrigin origin(String version, @Nullable String previousDigest) {
    String digest = "1".repeat(64);
    return InstalledAppOrigin.create(
        SAMPLE_APP_ID,
        version,
        digest,
        "catalog-a",
        "catalog-key",
        digest,
        digest,
        "publisher-key",
        "",
        "",
        "",
        "trusted_reviewed",
        "binding-a",
        digest,
        digest,
        digest,
        Instant.parse("2026-08-26T00:00:00Z"),
        previousDigest);
  }

  private static InstalledAppOrigin signedOrigin(AppBundleVerification verification) {
    return signedOrigin(APP_VERSION, verification, null);
  }

  private static InstalledAppOrigin signedOrigin(
      String version, AppBundleVerification verification, @Nullable String previousDigest) {
    String digest = "1".repeat(64);
    return InstalledAppOrigin.create(
        SAMPLE_APP_ID,
        version,
        digest,
        "catalog-a",
        "catalog-key",
        digest,
        digest,
        verification.keyId(),
        verification.keyFingerprintSha256(),
        verification.signedContentDigestSha256(),
        "",
        "trusted_reviewed",
        "binding-a",
        digest,
        digest,
        digest,
        Instant.parse("2026-08-26T00:00:00Z"),
        previousDigest);
  }

  private static Path createActiveTransaction(
      AppHostLayout layout, InstalledAppOrigin priorOrigin, boolean currentBundlePresent)
      throws IOException {
    Path active = layout.appMutationTransactionsDir().resolve(SAMPLE_APP_ID + ".active");
    Files.createDirectories(active);
    if (currentBundlePresent) {
      copyTree(layout.pathsFor(SAMPLE_APP_ID).installedRoot(), active.resolve("current-bundle"));
    }
    FileInstalledAppOriginStore.State before =
        new FileInstalledAppOriginStore.State(Optional.ofNullable(priorOrigin), Optional.empty());
    new FileInstalledAppOriginStore(active.resolve("origins")).restore(SAMPLE_APP_ID, before);
    Files.writeString(
        active.resolve("transaction.properties"),
        """
        schemaVersion=1
        appId=%s
        operation=%s
        currentBundlePresent=%s
        rollbackBundlePresent=false
        currentOriginPresent=%s
        rollbackOriginPresent=false
        """
            .formatted(
                SAMPLE_APP_ID,
                currentBundlePresent ? "catalog_update" : "catalog_install",
                currentBundlePresent,
                priorOrigin != null));
    return active;
  }

  private static void copyTree(Path source, Path target) throws IOException {
    try (var paths = Files.walk(source)) {
      for (Path path : paths.toList()) {
        Path destination = target.resolve(source.relativize(path));
        if (Files.isDirectory(path)) {
          Files.createDirectories(destination);
        } else {
          Files.createDirectories(destination.getParent());
          Files.copy(path, destination);
        }
      }
    }
  }

  private static boolean hasCommittedTransaction(AppHostLayout layout) throws IOException {
    try (var entries = Files.list(layout.appMutationTransactionsDir())) {
      return entries.anyMatch(path -> path.getFileName().toString().startsWith(".committed-"));
    }
  }

  private static void deleteTestTree(Path root) throws IOException {
    try (var paths = Files.walk(root)) {
      for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(path);
      }
    }
  }

  private LocalProcessAppHost allowUnsignedHost(
      Duration stopTimeout, AppEnv appEnv, AppSandboxProviders sandboxProviders) {
    return new LocalProcessAppHost(
        layout(),
        stopTimeout,
        new java.security.SecureRandom(),
        appEnv,
        TEST_TIMING,
        AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly(),
        sandboxProviders);
  }

  private LocalProcessAppHost allowUnsignedHostWithSingleRestartStormLimit() {
    return new LocalProcessAppHost(
        layout(),
        Duration.ofSeconds(1),
        new java.security.SecureRandom(),
        new AppEnv(),
        TEST_TIMING,
        AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly(),
        new LocalProcessAppHost.RestartStormPolicy(Duration.ofMinutes(5), 1));
  }

  private LocalProcessAppHost allowUnsignedHost(
      Duration stopTimeout,
      AppEnv appEnv,
      LocalProcessAppHost.ManagedTreeDeleter managedTreeDeleter) {
    return new LocalProcessAppHost(
        layout(),
        stopTimeout,
        new java.security.SecureRandom(),
        appEnv,
        TEST_TIMING,
        managedTreeDeleter,
        AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly());
  }

  private LocalProcessAppHost requireSignedHost(
      AppInstallVerificationPolicy.CopiedBundleVerifier verifier) {
    return new LocalProcessAppHost(
        layout(),
        Duration.ofSeconds(1),
        new java.security.SecureRandom(),
        new AppEnv(),
        TEST_TIMING,
        AppInstallVerificationPolicy.requireSigned(verifier));
  }

  private static LocalProcessAppHost exactIdentityHost(
      AppHostLayout layout, AppBundleVerifier newBundleVerifier, TrustedAppKeys trustedKeys) {
    AppBundleVerifier historicalVerifier =
        AppBundleVerifier.requireSignedForHistoricalVerification(trustedKeys);
    return new LocalProcessAppHost(
        layout,
        AppInstallVerificationPolicy.requireSignedWithIdentity(
            newBundleVerifier::verify, historicalVerifier::verify));
  }

  private LocalProcessAppHost signedHost(KeyPair keyPair) {
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(
            new TrustedAppKey(
                TEST_KEY_ID, AppBundleSignature.SIGNATURE_ALGORITHM, keyPair.getPublic()));
    return requireSignedHost(
        copiedBundleDirectory -> AppBundleVerifier.verify(copiedBundleDirectory, trustedKeys));
  }

  private AppHostLayout layout() {
    return new AppHostLayout(
        tempDir.resolve("data"), tempDir.resolve(CACHE_DIR_NAME), tempDir.resolve("run"));
  }

  private static AppSandboxProviders enforcedRestrictedProcessProviders() {
    return new AppSandboxProviders(
        new network.crypta.platform.apphost.sandbox.NoSandboxProvider(),
        new EnforcedRestrictedProcessProvider(),
        null);
  }

  private static AppSandboxProviders restartRejectingRestrictedProcessProviders() {
    return new AppSandboxProviders(
        new network.crypta.platform.apphost.sandbox.NoSandboxProvider(),
        new RestartRejectingRestrictedProcessProvider(),
        null);
  }

  private Path stageInstalledApp(String appId) throws IOException {
    return stageInstalledApp(appId, scriptContent(new AppEnv()), Map.of());
  }

  private Path signBundle(Path stagedDir, KeyPair keyPair) throws IOException {
    AppBundleSigner.sign(stagedDir, TEST_KEY_ID, keyPair.getPrivate());
    return stagedDir;
  }

  private Path stageInstalledRunnerApp(String scriptContent) throws IOException {
    return stageInstalledApp(RUNNER_APP_ID, scriptContent, Map.of());
  }

  private static void appendOnFailureRestartPolicy(Path stagedApp, long backoffMillis)
      throws IOException {
    appendOnFailureRestartPolicy(stagedApp, backoffMillis, 1);
  }

  private static void appendOnFailureRestartPolicy(
      Path stagedApp, long backoffMillis, int maxAttempts) throws IOException {
    Files.writeString(
        stagedApp.resolve(MANIFEST_FILE_NAME),
        """
        app.restart.policy=%s
        app.restart.maxAttempts=%d
        app.restart.backoff.ms=%d
        """
            .formatted("on-failure", maxAttempts, backoffMillis),
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);
  }

  private static void appendRequiredRestrictedSandbox(Path stagedApp) throws IOException {
    Files.writeString(
        stagedApp.resolve(MANIFEST_FILE_NAME),
        """
        sandbox.mode=restricted-process
        sandbox.required=true
        """,
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);
  }

  private static void appendOptionalRestrictedSandbox(Path stagedApp) throws IOException {
    Files.writeString(
        stagedApp.resolve(MANIFEST_FILE_NAME),
        """
        sandbox.mode=restricted-process
        sandbox.required=false
        """,
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);
  }

  private static void replaceManifestQuotasWithZero(Path stagedApp) throws IOException {
    Path manifestFile = stagedApp.resolve(MANIFEST_FILE_NAME);
    String manifest = Files.readString(manifestFile, StandardCharsets.UTF_8);
    manifest =
        manifest
            .replace("quota.data.bytes=4096", "quota.data.bytes=0")
            .replace("quota.cache.bytes=1024", "quota.cache.bytes=0");
    Files.writeString(manifestFile, manifest, StandardCharsets.UTF_8);
  }

  private static void removeManifestQuotas(Path stagedApp) throws IOException {
    Path manifestFile = stagedApp.resolve(MANIFEST_FILE_NAME);
    String manifest =
        Files.readString(manifestFile, StandardCharsets.UTF_8)
            .replace("quota.data.bytes=4096\n", "")
            .replace("quota.cache.bytes=1024\n", "");
    Files.writeString(manifestFile, manifest, StandardCharsets.UTF_8);
  }

  private Path stageInstalledApp(String appId, String scriptContent, Map<String, String> extraFiles)
      throws IOException {
    Path stagedDir = tempDir.resolve(STAGE_DIR_NAME).resolve(appId);
    return stageInstalledAppAt(stagedDir, appId, scriptContent, extraFiles);
  }

  private Path stageInstalledAppAt(
      Path stagedDir, String appId, String scriptContent, Map<String, String> extraFiles)
      throws IOException {
    return stageInstalledAppAt(stagedDir, appId, APP_VERSION, scriptContent, extraFiles);
  }

  private Path stageInstalledAppAt(
      Path stagedDir,
      String appId,
      String appVersion,
      String scriptContent,
      Map<String, String> extraFiles)
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Files.createDirectories(stagedDir);
    Path binDir = Files.createDirectories(stagedDir.resolve("bin"));
    String scriptName = scriptName(appEnv);
    Path scriptFile = binDir.resolve(scriptName);
    writeStageFile(scriptFile, scriptContent, appEnv);
    for (Map.Entry<String, String> extraFile : extraFiles.entrySet()) {
      writeStageFile(stagedDir.resolve(extraFile.getKey()), extraFile.getValue(), appEnv);
    }
    Files.writeString(stagedDir.resolve(CONTENT_FILE_NAME), "payload", StandardCharsets.UTF_8);
    Files.writeString(
        stagedDir.resolve(MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/%s
        app.ui.entry=/
        app.permissions=%s
        quota.data.bytes=4096
        quota.cache.bytes=1024
        """
            .formatted(
                appId, displayName(appId), appVersion, scriptName, STANDARD_PERMISSIONS_TEXT),
        StandardCharsets.UTF_8);
    return stagedDir;
  }

  private Path stageInstalledExecutableApp(
      String appId, String execRelativePath, String execContent, Map<String, String> extraFiles)
      throws IOException {
    return stageInstalledExecutableApp(appId, execRelativePath, execContent, extraFiles, true);
  }

  private Path stageInstalledExecutableApp(
      String appId,
      String execRelativePath,
      String execContent,
      Map<String, String> extraFiles,
      boolean executable)
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Path stagedDir = Files.createDirectories(tempDir.resolve(STAGE_DIR_NAME).resolve(appId));
    writeExecutableStageFile(stagedDir.resolve(execRelativePath), execContent, appEnv, executable);
    for (Map.Entry<String, String> extraFile : extraFiles.entrySet()) {
      writeStageFile(stagedDir.resolve(extraFile.getKey()), extraFile.getValue(), appEnv);
    }
    Files.writeString(stagedDir.resolve(CONTENT_FILE_NAME), "payload", StandardCharsets.UTF_8);
    Files.writeString(
        stagedDir.resolve(MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=%s
        app.ui.entry=/
        app.permissions=%s
        quota.data.bytes=4096
        quota.cache.bytes=1024
        """
            .formatted(
                appId,
                displayName(appId),
                APP_VERSION,
                execRelativePath,
                STANDARD_PERMISSIONS_TEXT),
        StandardCharsets.UTF_8);
    return stagedDir;
  }

  private RunningAppSnapshot runningSnapshot(String appId) {
    AppManifest manifest =
        new AppManifest(
            1,
            appId,
            displayName(appId),
            APP_VERSION,
            "bin/" + scriptName(new AppEnv()),
            "/",
            STANDARD_PERMISSIONS,
            4096L,
            1024L);
    InstalledAppPaths paths =
        new AppHostLayout(
                tempDir.resolve("data"), tempDir.resolve(CACHE_DIR_NAME), tempDir.resolve("run"))
            .pathsFor(appId);
    return new RunningAppSnapshot(manifest, paths, DEFAULT_TOKEN, 42L, Instant.EPOCH);
  }

  private static KeyPair generateEd25519KeyPair() {
    try {
      return KeyPairGenerator.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM).generateKeyPair();
    } catch (Exception exception) {
      throw new IllegalStateException("Failed to generate Ed25519 test key pair.", exception);
    }
  }

  @SuppressWarnings({"java:S3011"})
  private static void injectRunningProcess(
      LocalProcessAppHost host, String appId, RunningAppSnapshot snapshot, Process process)
      throws ReflectiveOperationException {
    injectRunningProcess(host, appId, snapshot, process, new CompletableFuture<>());
  }

  @SuppressWarnings({"unchecked", "java:S3011"})
  private static void injectRunningProcess(
      LocalProcessAppHost host,
      String appId,
      RunningAppSnapshot snapshot,
      Process process,
      CompletableFuture<Void> exitCleanup)
      throws ReflectiveOperationException {
    Field runningAppsField = LocalProcessAppHost.class.getDeclaredField("runningApps");
    runningAppsField.setAccessible(true);
    Map<String, Object> runningApps = (Map<String, Object>) runningAppsField.get(host);

    Class<?> runningProcessClass =
        Class.forName(LocalProcessAppHost.class.getName() + "$RunningProcess");
    Constructor<?> constructor =
        runningProcessClass.getDeclaredConstructor(
            Process.class,
            RunningAppSnapshot.class,
            CompletableFuture.class,
            List.class,
            int.class,
            int.class,
            boolean.class);
    constructor.setAccessible(true);
    Object runningProcess =
        constructor.newInstance(
            process, snapshot, exitCleanup, List.of(process.toHandle()), 0, 0, false);
    runningApps.put(appId, runningProcess);
  }

  @SuppressWarnings({"unchecked", "java:S3011"})
  private static Object runnerProcessEntry(LocalProcessAppHost host)
      throws ReflectiveOperationException {
    Field runningAppsField = LocalProcessAppHost.class.getDeclaredField("runningApps");
    runningAppsField.setAccessible(true);
    Map<String, Object> runningApps = (Map<String, Object>) runningAppsField.get(host);
    return runningApps.get(RUNNER_APP_ID);
  }

  @SuppressWarnings("java:S3011")
  private static boolean invokePreserveRunnerState(LocalProcessAppHost host, Object runningProcess)
      throws ReflectiveOperationException {
    Class<?> runningProcessClass =
        Class.forName(LocalProcessAppHost.class.getName() + "$RunningProcess");
    Method preserveRunningState =
        LocalProcessAppHost.class.getDeclaredMethod(
            "preserveRunningState", String.class, runningProcessClass);
    preserveRunningState.setAccessible(true);
    return (boolean) preserveRunningState.invoke(host, RUNNER_APP_ID, runningProcess);
  }

  @SuppressWarnings("java:S3011")
  private static void invokeCapturePostExitProcessTreeHandoff(
      LocalProcessAppHost host, Process process) throws ReflectiveOperationException {
    Method capturePostExitProcessTreeHandoff =
        LocalProcessAppHost.class.getDeclaredMethod(
            "capturePostExitProcessTreeHandoff", String.class, Process.class);
    capturePostExitProcessTreeHandoff.setAccessible(true);
    capturePostExitProcessTreeHandoff.invoke(host, RUNNER_APP_ID, process);
  }

  private static void invokeParseRunnerTokenTrackedProcesses(Process process)
      throws ReflectiveOperationException, IOException {
    MethodHandle parseTokenTrackedProcesses =
        MethodHandles.privateLookupIn(LocalProcessAppHost.class, MethodHandles.lookup())
            .findStatic(
                LocalProcessAppHost.class,
                "parseTokenTrackedProcesses",
                MethodType.methodType(List.class, Process.class, String.class, String.class));
    try {
      parseTokenTrackedProcesses.invoke(process, DEFAULT_TOKEN, RUNNER_APP_ID);
    } catch (Throwable throwable) {
      switch (throwable) {
        case IOException ioException -> throw ioException;
        case RuntimeException runtimeException -> throw runtimeException;
        case Error error -> throw error;
        case ReflectiveOperationException reflectiveOperationException ->
            throw reflectiveOperationException;
        default -> {
          // do nothing
        }
      }
      throw new ReflectiveOperationException(
          "failed to invoke parseTokenTrackedProcesses", throwable);
    }
  }

  private static void writeStageFile(Path file, String content, AppEnv appEnv) throws IOException {
    Files.createDirectories(parentOrThrow(file));
    Files.writeString(file, content, StandardCharsets.UTF_8);
    if (!appEnv.isWindows() && fileNameOrThrow(file).endsWith(".sh")) {
      assertTrue(file.toFile().setExecutable(true, false));
    }
  }

  private static void writeExecutableStageFile(
      Path file, String content, AppEnv appEnv, boolean executable) throws IOException {
    Files.createDirectories(parentOrThrow(file));
    Files.writeString(file, content, StandardCharsets.UTF_8);
    if (!appEnv.isWindows()) {
      assertTrue(file.toFile().setExecutable(executable, false));
    }
  }

  private static Path parentOrThrow(Path path) {
    Path parent = path.getParent();
    if (parent == null) {
      throw new AssertionError("Expected parent for path " + path);
    }
    return parent;
  }

  private static String fileNameOrThrow(Path path) {
    Path fileName = path.getFileName();
    if (fileName == null) {
      throw new AssertionError("Expected file name for path " + path);
    }
    return fileName.toString();
  }

  private static String displayName(String appId) {
    return switch (appId) {
      case RUNNER_APP_ID -> "Runner App";
      case SAMPLE_APP_ID -> "Sample App";
      case MIXED_CASE_APP_ID -> "Mixed Case App";
      default -> "Duplicate App";
    };
  }

  private static String scriptName(AppEnv appEnv) {
    return appEnv.isWindows() ? "launch.cmd" : "launch.sh";
  }

  private static String scriptContent(AppEnv appEnv) {
    if (appEnv.isWindows()) {
      return """
      @echo off
      setlocal EnableExtensions
      set > "%CRYPTAD_APP_RUN_DIR%\\captured-env.txt"
      :loop
      timeout /t 1 /nobreak >nul
      goto loop
      """;
    }
    return """
    #!/bin/sh
    set -eu
    env > "$CRYPTAD_APP_RUN_DIR/captured-env.txt"
    while :; do
      sleep %s
    done
    """
        .formatted(TEST_LOOP_SLEEP_SECONDS);
  }

  private static String secondsLiteral(Duration duration) {
    return String.format(java.util.Locale.ROOT, "%.3f", duration.toNanos() / 1_000_000_000.0d);
  }

  private static final class EnforcedRestrictedProcessProvider implements AppSandboxProvider {
    @Override
    public String providerName() {
      return BUBBLEWRAP_PROVIDER_NAME;
    }

    @Override
    public boolean supports(AppSandboxPolicy policy) {
      return policy.mode() == network.crypta.platform.appdist.AppSandboxMode.RESTRICTED_PROCESS;
    }

    @Override
    public AppSandboxStatus inactiveStatus(AppSandboxPolicy policy) {
      return enforcedRestrictedProcessStatus(policy, false);
    }

    @Override
    public AppSandboxLaunchPlan prepareLaunch(AppSandboxLaunchContext context) {
      return new AppSandboxLaunchPlan(
          context.command(),
          context.environment(),
          context.workingDirectory(),
          enforcedRestrictedProcessStatus(context.policy(), true));
    }
  }

  private static final class RestartRejectingRestrictedProcessProvider
      implements AppSandboxProvider {
    private final AtomicInteger launchAttempts = new AtomicInteger();

    @Override
    public String providerName() {
      return BUBBLEWRAP_PROVIDER_NAME;
    }

    @Override
    public boolean supports(AppSandboxPolicy policy) {
      return policy.mode() == AppSandboxMode.RESTRICTED_PROCESS;
    }

    @Override
    public AppSandboxStatus inactiveStatus(AppSandboxPolicy policy) {
      return enforcedRestrictedProcessStatus(policy, false);
    }

    @Override
    public AppSandboxLaunchPlan prepareLaunch(AppSandboxLaunchContext context)
        throws AppSandboxException {
      if (launchAttempts.incrementAndGet() > 1) {
        throw AppSandboxException.unsupportedRequired(
            AppSandboxStatus.unsupported(
                context.policy(), "restricted-process sandbox is not available on this host"));
      }
      return new AppSandboxLaunchPlan(
          context.command(),
          context.environment(),
          context.workingDirectory(),
          enforcedRestrictedProcessStatus(context.policy(), true));
    }
  }

  private static AppSandboxStatus enforcedRestrictedProcessStatus(
      AppSandboxPolicy policy, boolean active) {
    return new AppSandboxStatus(
        policy.mode(),
        policy.required(),
        AppSandboxSupportLevel.ENFORCED,
        BUBBLEWRAP_PROVIDER_NAME,
        active,
        active
            ? "Linux bubblewrap sandbox active"
            : "Linux bubblewrap sandbox will be used on start",
        List.of(
            active
                ? "Filesystem sandbox active for installed bundle and AppHost-managed mutable"
                    + " directories"
                : "Filesystem sandbox will cover installed bundle and AppHost-managed mutable"
                    + " directories",
            "CPU, memory, and network restrictions are not enforced by this provider"));
  }

  private static String immediateExitScriptContent(AppEnv appEnv) {
    if (appEnv.isWindows()) {
      return """
      @echo off
      exit /b 0
      """;
    }
    return EXIT_ZERO_SCRIPT;
  }

  private static void assertCapturedEnvironment(
      InstalledAppSnapshot installation, RunningAppSnapshot running, String capture) {
    assertTrue(capture.contains("CRYPTAD_APP_ID=" + RUNNER_APP_ID));
    assertTrue(capture.contains("CRYPTAD_APP_NAME=Runner App"));
    assertTrue(capture.contains("CRYPTAD_APP_VERSION=" + APP_VERSION));
    assertTrue(capture.contains("CRYPTAD_APP_DATA_DIR=" + installation.paths().dataDir()));
    assertTrue(capture.contains("CRYPTAD_APP_CACHE_DIR=" + installation.paths().cacheDir()));
    assertTrue(capture.contains("CRYPTAD_APP_RUN_DIR=" + installation.paths().runDir()));
    assertTrue(capture.contains(APP_TOKEN_ENV_ASSIGNMENT_PREFIX + running.token()));
    assertTrue(capture.contains("CRYPTAD_APP_PERMISSIONS=" + STANDARD_PERMISSIONS_TEXT));
    assertTrue(capture.contains("CRYPTAD_APP_UI_MODE=shell-panel"));
    assertTrue(capture.contains("CRYPTAD_APP_UI_ENTRY=/"));
  }

  private static long processLogRetainedBytes(InstalledAppPaths paths) {
    return AppHost.DEFAULT_PROCESS_LOG_MAX_BYTES
        + AppHostTokenRedactor.redactionOverlapBytes(null, paths);
  }

  private static void assertInstallationPathsRemoved(InstalledAppSnapshot installation) {
    assertFalse(Files.exists(installation.paths().installedRoot()));
    assertFalse(Files.exists(installation.paths().dataDir()));
    assertFalse(Files.exists(installation.paths().cacheDir()));
    assertFalse(Files.exists(installation.paths().runDir()));
  }

  private static AppHostException installExpectingAppHostException(AppHost host, Path stagedApp)
      throws Exception {
    //noinspection resource
    ExecutorService executor =
        Executors.newSingleThreadExecutor(
            runnable -> {
              Thread thread = new Thread(runnable, "apphost-install-test");
              thread.setDaemon(true);
              return thread;
            });
    try {
      ExecutionException exception =
          installFailure(executor.submit(() -> host.installFromDirectory(stagedApp)), stagedApp);
      assertInstanceOf(AppHostException.class, exception.getCause());
      return (AppHostException) exception.getCause();
    } catch (TimeoutException e) {
      throw new AssertionError("installFromDirectory hung on named pipe: " + stagedApp, e);
    } finally {
      executor.shutdownNow();
    }
  }

  private static ExecutionException installFailure(
      java.util.concurrent.Future<InstalledAppSnapshot> installFuture, Path stagedApp)
      throws InterruptedException, TimeoutException {
    try {
      installFuture.get(5, TimeUnit.SECONDS);
      throw new AssertionError("expected installFromDirectory() to fail for " + stagedApp);
    } catch (ExecutionException e) {
      return e;
    }
  }

  private static int waitForExit(Process process) throws IOException, InterruptedException {
    if (!process.waitFor(5, TimeUnit.SECONDS)) {
      process.destroyForcibly();
      throw new IOException("timed out waiting for process to exit: " + process.pid());
    }
    return process.exitValue();
  }

  private static RunningAppSnapshot waitForRunningApp(AppHost host, String appId) {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (System.nanoTime() < deadline) {
      Optional<RunningAppSnapshot> running = host.status(appId);
      if (running.isPresent()) {
        return running.orElseThrow();
      }
      pausePolling("interrupted while waiting for app to be running: " + appId);
    }
    throw new AssertionError("timed out waiting for app to be running: " + appId);
  }

  private static AppRuntimeStatusSnapshot waitForRuntimeState(AppHost host, AppRuntimeState state)
      throws IOException {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (System.nanoTime() < deadline) {
      AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
      if (status.state() == state) {
        return status;
      }
      pausePolling("interrupted while waiting for app runtime state: " + RUNNER_APP_ID);
    }
    throw new AssertionError("timed out waiting for app runtime state: " + RUNNER_APP_ID);
  }

  private static AppRuntimeStatusSnapshot waitForRunnerRestarted(AppHost host) throws IOException {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    AppRuntimeStatusSnapshot lastStatus = null;
    while (System.nanoTime() < deadline) {
      AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
      lastStatus = status;
      if (status.state() == AppRuntimeState.RUNNING && status.currentRestartAttempt() == 1) {
        return status;
      }
      pausePolling("interrupted while waiting for app runtime restart: " + RUNNER_APP_ID);
    }
    throw new AssertionError(
        "timed out waiting for app runtime restart: " + RUNNER_APP_ID + " last=" + lastStatus);
  }

  private static AppRuntimeStatusSnapshot waitForCrashedInactiveSandboxStatus(AppHost host)
      throws IOException {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    AppRuntimeStatusSnapshot lastStatus = null;
    while (System.nanoTime() < deadline) {
      AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
      lastStatus = status;
      if (status.state() == AppRuntimeState.CRASHED
          && !status.running()
          && !status.sandboxStatus().active()) {
        return status;
      }
      pausePolling("interrupted while waiting for inactive crashed sandbox: " + RUNNER_APP_ID);
    }
    throw new AssertionError(
        "timed out waiting for inactive crashed sandbox: " + RUNNER_APP_ID + " last=" + lastStatus);
  }

  private static AppRuntimeStatusSnapshot waitForRestartStormWarning(AppHost host)
      throws IOException {
    long deadline = System.nanoTime() + Duration.ofSeconds(12).toNanos();
    AppRuntimeStatusSnapshot lastStatus = null;
    while (System.nanoTime() < deadline) {
      AppRuntimeStatusSnapshot status = host.runtimeStatus(RUNNER_APP_ID);
      lastStatus = status;
      if (status.warnings().contains(RESTART_STORM_WARNING)) {
        return status;
      }
      pausePolling("interrupted while waiting for app runtime warning: " + RUNNER_APP_ID);
    }
    throw new AssertionError(
        "timed out waiting for app runtime warning: " + RUNNER_APP_ID + " last=" + lastStatus);
  }

  private static void waitForNotRunning(AppHost host) {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (System.nanoTime() < deadline) {
      if (host.status(RUNNER_APP_ID).isEmpty()
          && host.listRunning().stream().noneMatch(app -> RUNNER_APP_ID.equals(app.appId()))) {
        return;
      }
      pausePolling("interrupted while waiting for app to stop running: " + RUNNER_APP_ID);
    }
    throw new AssertionError("timed out waiting for app to stop running: " + RUNNER_APP_ID);
  }

  private static RunningAppSnapshot waitForRunningPid(AppHost host, long pid) {
    return waitForRunningPid(host, RUNNER_APP_ID, pid);
  }

  private static RunningAppSnapshot waitForRunningPid(AppHost host, String appId, long pid) {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (System.nanoTime() < deadline) {
      Optional<RunningAppSnapshot> running = host.status(appId);
      if (running.isPresent() && running.orElseThrow().pid() == pid) {
        return running.orElseThrow();
      }
      pausePolling("interrupted while waiting for app " + appId + " to report pid " + pid);
    }
    throw new AssertionError("timed out waiting for app " + appId + " to report pid " + pid);
  }

  private static void waitForFileContent(Path file, String expectedContent) throws IOException {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (System.nanoTime() < deadline) {
      if (Files.isRegularFile(file)
          && expectedContent.equals(Files.readString(file, StandardCharsets.UTF_8))) {
        return;
      }
      pausePolling("interrupted while waiting for file content: " + file);
    }
    throw new AssertionError("timed out waiting for file content: " + file);
  }

  private static void waitForProcessExit(long pid) throws IOException {
    ProcessHandle handle = ProcessHandle.of(pid).orElse(null);
    if (handle == null || !isEffectivelyAlive(handle)) {
      return;
    }
    try {
      handle.onExit().get(5, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("interrupted while waiting for process " + pid + " to exit", e);
    } catch (ExecutionException e) {
      throw new IOException("failed while waiting for process " + pid + " to exit", e);
    } catch (TimeoutException e) {
      throw new AssertionError("timed out waiting for child process " + pid + " to exit", e);
    }
  }

  private static boolean isEffectivelyAlive(ProcessHandle handle) {
    return handle.isAlive() && !isZombieProcess(handle);
  }

  private static boolean isZombieProcess(ProcessHandle handle) {
    Path statFile = Path.of("/proc", Long.toString(handle.pid()), "stat");
    if (!Files.isReadable(statFile)) {
      return false;
    }
    try {
      String stat = Files.readString(statFile);
      int commandEnd = stat.lastIndexOf(')');
      return commandEnd >= 0
          && commandEnd + 2 < stat.length()
          && stat.charAt(commandEnd + 2) == 'Z';
    } catch (IOException _) {
      return false;
    }
  }

  private static void pausePolling(String interruptMessage) {
    LockSupport.parkNanos(POLL_INTERVAL_NANOS);
    if (Thread.interrupted()) {
      Thread.currentThread().interrupt();
      throw new AssertionError(interruptMessage, new InterruptedException(interruptMessage));
    }
  }

  private static String resolveTrustedMkfifoCommand() {
    for (Path trustedDir :
        List.of(Path.of("/usr/bin"), Path.of("/bin"), Path.of("/usr/sbin"), Path.of("/sbin"))) {
      Path candidate = trustedDir.resolve(MKFIFO_COMMAND);
      if (Files.isExecutable(candidate)) {
        return candidate.toString();
      }
    }
    throw new AssertionError("trusted command not found: " + MKFIFO_COMMAND);
  }

  private static String windowsCommandInterpreter() {
    String comSpec = System.getenv("ComSpec");
    return comSpec != null && !comSpec.isBlank() ? comSpec : "cmd.exe";
  }

  private static void waitForFile(Path file) throws IOException {
    if (Files.isRegularFile(file)) {
      return;
    }

    Path parent = file.getParent();
    if (parent == null) {
      throw new AssertionError("file has no parent: " + file);
    }

    long timeoutMillis = Duration.ofSeconds(10).toMillis();
    try (WatchService watchService = parent.getFileSystem().newWatchService()) {
      parent.register(
          watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);
      long deadline = System.nanoTime() + Duration.ofMillis(timeoutMillis).toNanos();
      while (System.nanoTime() < deadline) {
        WatchKey key = pollWatchKey(watchService, deadline, file);
        if (Files.isRegularFile(file)) {
          return;
        }
        if (key != null) {
          if (isWatchedFilePresent(file, key)) {
            return;
          }
          if (!key.reset()) {
            throw new AssertionError("watch service closed before " + file + " appeared");
          }
        }
      }
      if (Files.isRegularFile(file)) {
        return;
      }
    }
    throw new AssertionError("timed out waiting for " + file);
  }

  private static long waitForPidFileValue(Path file) throws IOException {
    ObservedPid observedPid = tryReadPidFileValue(file);
    if (observedPid.pid() != null) {
      return observedPid.pid();
    }

    Path parent = file.getParent();
    if (parent == null) {
      throw new AssertionError("file has no parent: " + file);
    }

    long timeoutMillis = Duration.ofSeconds(10).toMillis();
    try (WatchService watchService = parent.getFileSystem().newWatchService()) {
      parent.register(
          watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);
      long deadline = System.nanoTime() + Duration.ofMillis(timeoutMillis).toNanos();
      while (System.nanoTime() < deadline) {
        WatchKey key = pollWatchKey(watchService, deadline, file);
        observedPid = tryReadPidFileValue(file);
        if (observedPid.pid() != null) {
          return observedPid.pid();
        }
        if (key != null && !key.reset()) {
          throw new AssertionError("watch service closed before " + file + " became readable");
        }
      }
    }

    observedPid = tryReadPidFileValue(file);
    if (observedPid.pid() != null) {
      return observedPid.pid();
    }

    throw new AssertionError(
        "timed out waiting for numeric pid in "
            + file
            + (observedPid.contents() == null
                ? ""
                : "; last observed contents: '" + observedPid.contents() + "'"));
  }

  private static WatchService watchForCreatedEntries(Path directory) throws IOException {
    WatchService watchService = directory.getFileSystem().newWatchService();
    try {
      directory.register(watchService, StandardWatchEventKinds.ENTRY_CREATE);
      return watchService;
    } catch (IOException | RuntimeException failure) {
      try {
        watchService.close();
      } catch (IOException cleanupFailure) {
        failure.addSuppressed(cleanupFailure);
      }
      throw failure;
    }
  }

  private static void assertNoCreatedEntry(WatchService watchService, Path directory)
      throws IOException {
    long deadline = System.nanoTime() + Duration.ofMillis(250).toNanos();
    WatchKey key = pollWatchKey(watchService, deadline, directory);
    assertNull(key, "update precondition rejection must not open a persistent mutation");
  }

  private static ObservedPid tryReadPidFileValue(Path file) throws IOException {
    if (!Files.isRegularFile(file)) {
      return new ObservedPid(null, null);
    }

    String contents = Files.readString(file, StandardCharsets.UTF_8).trim();
    if (contents.isEmpty()) {
      return new ObservedPid(null, contents);
    }

    try {
      return new ObservedPid(Long.parseLong(contents), contents);
    } catch (NumberFormatException _) {
      return new ObservedPid(null, contents);
    }
  }

  private static WatchKey pollWatchKey(WatchService watchService, long deadline, Path file)
      throws IOException {
    long remainingNanos = deadline - System.nanoTime();
    if (remainingNanos <= 0L) {
      return null;
    }
    try {
      return watchService.poll(remainingNanos, TimeUnit.NANOSECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("interrupted while waiting for " + file, e);
    }
  }

  private static boolean isWatchedFilePresent(Path file, WatchKey key) {
    for (WatchEvent<?> event : key.pollEvents()) {
      if (event.context() instanceof Path changed
          && changed.equals(file.getFileName())
          && Files.isRegularFile(file)) {
        return true;
      }
    }
    return false;
  }

  private record ObservedPid(@Nullable Long pid, @Nullable String contents) {}

  private static final class LateChildSpawningProcess extends Process {
    private final long pid;
    private final ProcessHandle handle;
    private final ProcessHandle childHandle;
    private boolean rootAlive = true;
    private boolean childSpawned;

    private LateChildSpawningProcess(long pid, long childPid) {
      this.pid = pid;
      this.handle = new LateChildSpawningProcessHandle();
      this.childHandle = new LinkedProcessHandle(childPid, handle, true);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return !rootAlive;
    }

    @Override
    public int exitValue() {
      if (rootAlive) {
        throw new IllegalThreadStateException("process is still running");
      }
      return 0;
    }

    @Override
    public void destroy() {
      childSpawned = true;
      rootAlive = false;
    }

    @Override
    public Process destroyForcibly() {
      destroy();
      return this;
    }

    @Override
    public boolean isAlive() {
      return rootAlive;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public ProcessHandle toHandle() {
      return handle;
    }

    private final class LateChildSpawningProcessHandle implements ProcessHandle {
      @Override
      public long pid() {
        return pid;
      }

      @Override
      public Info info() {
        return new Info() {
          @Override
          public Optional<String> command() {
            return Optional.empty();
          }

          @Override
          public Optional<String> commandLine() {
            return Optional.empty();
          }

          @Override
          public Optional<String[]> arguments() {
            return Optional.empty();
          }

          @Override
          public Optional<Instant> startInstant() {
            return Optional.empty();
          }

          @Override
          public Optional<Duration> totalCpuDuration() {
            return Optional.empty();
          }

          @Override
          public Optional<String> user() {
            return Optional.empty();
          }
        };
      }

      @Override
      public CompletableFuture<ProcessHandle> onExit() {
        return rootAlive ? new CompletableFuture<>() : CompletableFuture.completedFuture(this);
      }

      @Override
      public boolean supportsNormalTermination() {
        return true;
      }

      @Override
      public boolean destroy() {
        LateChildSpawningProcess.this.destroy();
        return true;
      }

      @Override
      public boolean destroyForcibly() {
        return destroy();
      }

      @Override
      public boolean isAlive() {
        return rootAlive;
      }

      @Override
      public Optional<ProcessHandle> parent() {
        return Optional.empty();
      }

      @Override
      public java.util.stream.Stream<ProcessHandle> children() {
        return childSpawned
            ? java.util.stream.Stream.of(childHandle)
            : java.util.stream.Stream.empty();
      }

      @Override
      public java.util.stream.Stream<ProcessHandle> descendants() {
        return children();
      }

      @Override
      public int compareTo(ProcessHandle other) {
        return Long.compare(pid, other.pid());
      }

      @Override
      public boolean equals(Object other) {
        return other instanceof ProcessHandle otherHandle && pid == otherHandle.pid();
      }

      @Override
      public int hashCode() {
        return Long.hashCode(pid);
      }
    }
  }

  private static final class LateRecoveredChildProcess extends Process {
    private final long pid;
    private final ProcessHandle handle;
    private boolean rootAlive = true;

    private LateRecoveredChildProcess(long pid, long childPid, int childAliveChecksBeforeExit) {
      this.pid = pid;
      this.handle = new LateRecoveredChildProcessHandle(childPid, childAliveChecksBeforeExit);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return !rootAlive;
    }

    @Override
    public int exitValue() {
      if (rootAlive) {
        throw new IllegalThreadStateException("process is still running");
      }
      return 0;
    }

    @Override
    public void destroy() {
      rootAlive = false;
    }

    @Override
    public Process destroyForcibly() {
      destroy();
      return this;
    }

    @Override
    public boolean isAlive() {
      return rootAlive;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public ProcessHandle toHandle() {
      return handle;
    }

    private final class LateRecoveredChildProcessHandle implements ProcessHandle {
      private final ProcessHandle childHandle;
      private final AtomicInteger deferredChildVisibilityChecks = new AtomicInteger(1);

      private LateRecoveredChildProcessHandle(long childPid, int childAliveChecksBeforeExit) {
        this.childHandle = new FadingProcessHandle(childPid, childAliveChecksBeforeExit);
      }

      @Override
      public long pid() {
        return pid;
      }

      @Override
      public Info info() {
        return new Info() {
          @Override
          public Optional<String> command() {
            return Optional.empty();
          }

          @Override
          public Optional<String> commandLine() {
            return Optional.empty();
          }

          @Override
          public Optional<String[]> arguments() {
            return Optional.empty();
          }

          @Override
          public Optional<Instant> startInstant() {
            return Optional.empty();
          }

          @Override
          public Optional<Duration> totalCpuDuration() {
            return Optional.empty();
          }

          @Override
          public Optional<String> user() {
            return Optional.empty();
          }
        };
      }

      @Override
      public CompletableFuture<ProcessHandle> onExit() {
        return rootAlive ? new CompletableFuture<>() : CompletableFuture.completedFuture(this);
      }

      @Override
      public boolean supportsNormalTermination() {
        return true;
      }

      @Override
      public boolean destroy() {
        LateRecoveredChildProcess.this.destroy();
        return true;
      }

      @Override
      public boolean destroyForcibly() {
        return destroy();
      }

      @Override
      public boolean isAlive() {
        return rootAlive;
      }

      @Override
      public Optional<ProcessHandle> parent() {
        return Optional.empty();
      }

      @Override
      public java.util.stream.Stream<ProcessHandle> children() {
        if (rootAlive) {
          return java.util.stream.Stream.empty();
        }
        int checksRemaining =
            deferredChildVisibilityChecks.getAndUpdate(current -> Math.max(0, current - 1));
        if (checksRemaining > 0) {
          return java.util.stream.Stream.empty();
        }
        return java.util.stream.Stream.of(childHandle);
      }

      @Override
      public java.util.stream.Stream<ProcessHandle> descendants() {
        return children();
      }

      @Override
      public int compareTo(ProcessHandle other) {
        return Long.compare(pid, other.pid());
      }

      @Override
      public boolean equals(Object other) {
        return other instanceof ProcessHandle otherHandle && pid == otherHandle.pid();
      }

      @Override
      public int hashCode() {
        return Long.hashCode(pid);
      }
    }
  }

  private static final class NonStoppingProcess extends Process {
    private final long pid;
    private final ProcessHandle handle;

    private NonStoppingProcess(long pid) {
      this.pid = pid;
      this.handle = new NonStoppingProcessHandle(pid);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      throw new UnsupportedOperationException("waitFor() not used by this test");
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return false;
    }

    @Override
    public int exitValue() {
      throw new IllegalThreadStateException("process is still running");
    }

    @Override
    public void destroy() {
      // Intentionally blank: this fake process ignores graceful termination so stop() times out.
    }

    @Override
    public Process destroyForcibly() {
      destroy();
      return this;
    }

    @Override
    public boolean isAlive() {
      return true;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public ProcessHandle toHandle() {
      return handle;
    }
  }

  private record NonStoppingProcessHandle(long pid) implements ProcessHandle {
    @Override
    public Info info() {
      return new Info() {
        @Override
        public java.util.Optional<String> command() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> commandLine() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String[]> arguments() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Instant> startInstant() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Duration> totalCpuDuration() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> user() {
          return java.util.Optional.empty();
        }
      };
    }

    @Override
    public CompletableFuture<ProcessHandle> onExit() {
      return new CompletableFuture<>();
    }

    @Override
    public boolean supportsNormalTermination() {
      return true;
    }

    @Override
    public boolean destroy() {
      return false;
    }

    @Override
    public boolean destroyForcibly() {
      return false;
    }

    @Override
    public boolean isAlive() {
      return true;
    }

    @Override
    public java.util.Optional<ProcessHandle> parent() {
      return java.util.Optional.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> children() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> descendants() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public int compareTo(ProcessHandle other) {
      return Long.compare(pid, other.pid());
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof ProcessHandle handle && pid == handle.pid();
    }

    @Override
    public int hashCode() {
      return Long.hashCode(pid);
    }
  }

  private static final class CleanExitedProcessWithTransientChild extends Process {
    private final long pid;
    private final ProcessHandle handle;

    private CleanExitedProcessWithTransientChild(
        long pid, long childPid, int childAliveChecksBeforeExit) {
      this(pid, new FadingProcessHandle(childPid, childAliveChecksBeforeExit));
    }

    private CleanExitedProcessWithTransientChild(long pid, ProcessHandle childHandle) {
      this.pid = pid;
      this.handle = new CleanExitedProcessWithTransientChildHandle(childHandle);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return true;
    }

    @Override
    public int exitValue() {
      return 0;
    }

    @Override
    public void destroy() {
      // Intentionally blank: this fake process already exits.
    }

    @Override
    public Process destroyForcibly() {
      return this;
    }

    @Override
    public boolean isAlive() {
      return false;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public ProcessHandle toHandle() {
      return handle;
    }

    private final class CleanExitedProcessWithTransientChildHandle implements ProcessHandle {
      private final ProcessHandle childHandle;

      private CleanExitedProcessWithTransientChildHandle(ProcessHandle childHandle) {
        this.childHandle = childHandle;
      }

      @Override
      public long pid() {
        return pid;
      }

      @Override
      public Info info() {
        return new Info() {
          @Override
          public java.util.Optional<String> command() {
            return java.util.Optional.empty();
          }

          @Override
          public java.util.Optional<String> commandLine() {
            return java.util.Optional.empty();
          }

          @Override
          public java.util.Optional<String[]> arguments() {
            return java.util.Optional.empty();
          }

          @Override
          public java.util.Optional<Instant> startInstant() {
            return java.util.Optional.empty();
          }

          @Override
          public java.util.Optional<Duration> totalCpuDuration() {
            return java.util.Optional.empty();
          }

          @Override
          public java.util.Optional<String> user() {
            return java.util.Optional.empty();
          }
        };
      }

      @Override
      public CompletableFuture<ProcessHandle> onExit() {
        return CompletableFuture.completedFuture(this);
      }

      @Override
      public boolean supportsNormalTermination() {
        return true;
      }

      @Override
      public boolean destroy() {
        return true;
      }

      @Override
      public boolean destroyForcibly() {
        return true;
      }

      @Override
      public boolean isAlive() {
        return false;
      }

      @Override
      public java.util.Optional<ProcessHandle> parent() {
        return java.util.Optional.empty();
      }

      @Override
      public java.util.stream.Stream<ProcessHandle> children() {
        return java.util.stream.Stream.of(childHandle);
      }

      @Override
      public java.util.stream.Stream<ProcessHandle> descendants() {
        return children();
      }

      @Override
      public int compareTo(ProcessHandle other) {
        return Long.compare(pid, other.pid());
      }

      @Override
      public boolean equals(Object other) {
        return other instanceof ProcessHandle otherHandle && pid == otherHandle.pid();
      }

      @Override
      public int hashCode() {
        return Long.hashCode(pid);
      }
    }
  }

  private static final class ExitedProcess extends Process {
    private final long pid;
    private final ProcessHandle handle;

    private ExitedProcess(long pid) {
      this.pid = pid;
      this.handle = new ExitedProcessHandle(pid);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return true;
    }

    @Override
    public int exitValue() {
      return 0;
    }

    @Override
    public void destroy() {
      // Intentionally blank: this fake process already exits.
    }

    @Override
    public Process destroyForcibly() {
      return this;
    }

    @Override
    public boolean isAlive() {
      return false;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public ProcessHandle toHandle() {
      return handle;
    }
  }

  private static final class FadingProcess extends Process {
    private final long pid;
    private final ProcessHandle handle;

    private FadingProcess(long pid, int aliveChecksBeforeExit) {
      this.pid = pid;
      this.handle = new FadingProcessHandle(pid, aliveChecksBeforeExit);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return !handle.isAlive();
    }

    @Override
    public int exitValue() {
      return 0;
    }

    @Override
    public void destroy() {
      // Intentionally blank: the handle simulates lifecycle.
    }

    @Override
    public Process destroyForcibly() {
      return this;
    }

    @Override
    public boolean isAlive() {
      return handle.isAlive();
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public ProcessHandle toHandle() {
      return handle;
    }
  }

  private static final class FailingInputProcess extends Process {
    private final InputStream inputStream;

    private FailingInputProcess(byte[] prefixBytes) {
      this.inputStream = new FailingInputStream(prefixBytes);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return inputStream;
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return true;
    }

    @Override
    public int exitValue() {
      return 0;
    }

    @Override
    public void destroy() {
      // Intentionally blank: this fake process exists only to expose a failing input stream.
    }

    @Override
    public Process destroyForcibly() {
      return this;
    }

    @Override
    public boolean isAlive() {
      return false;
    }

    @Override
    public long pid() {
      return 0L;
    }

    @Override
    public ProcessHandle toHandle() {
      return new ExitedProcessHandle(0L);
    }
  }

  private static final class FailingInputStream extends InputStream {
    private final byte[] prefixBytes;
    private int offset;

    private FailingInputStream(byte[] prefixBytes) {
      this.prefixBytes = prefixBytes;
    }

    @Override
    public int read() throws IOException {
      if (offset < prefixBytes.length) {
        return prefixBytes[offset++] & 0xFF;
      }
      throw new IOException("simulated ps stream failure");
    }

    @Override
    public int read(byte @NonNull [] buffer, int off, int len) throws IOException {
      if (offset < prefixBytes.length) {
        int bytesToCopy = Math.min(len, prefixBytes.length - offset);
        System.arraycopy(prefixBytes, offset, buffer, off, bytesToCopy);
        offset += bytesToCopy;
        return bytesToCopy;
      }
      throw new IOException("simulated ps stream failure");
    }
  }

  private static final class LinkedProcessHandle implements ProcessHandle {
    private final long pid;
    private final ProcessHandle parent;
    private final boolean alive;

    private LinkedProcessHandle(long pid, ProcessHandle parent, boolean alive) {
      this.pid = pid;
      this.parent = parent;
      this.alive = alive;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public Info info() {
      return new Info() {
        @Override
        public java.util.Optional<String> command() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> commandLine() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String[]> arguments() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Instant> startInstant() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Duration> totalCpuDuration() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> user() {
          return java.util.Optional.empty();
        }
      };
    }

    @Override
    public CompletableFuture<ProcessHandle> onExit() {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public boolean supportsNormalTermination() {
      return true;
    }

    @Override
    public boolean destroy() {
      return false;
    }

    @Override
    public boolean destroyForcibly() {
      return false;
    }

    @Override
    public boolean isAlive() {
      return alive;
    }

    @Override
    public java.util.Optional<ProcessHandle> parent() {
      return java.util.Optional.ofNullable(parent);
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> children() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> descendants() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public int compareTo(ProcessHandle other) {
      return Long.compare(pid, other.pid());
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof ProcessHandle handle && pid == handle.pid();
    }

    @Override
    public int hashCode() {
      return Long.hashCode(pid);
    }
  }

  private static final class InfoProcessHandle implements ProcessHandle {
    private final long pid;
    private final ProcessHandle parent;
    private final boolean alive;
    private final @Nullable String command;
    private final @Nullable String commandLine;
    private final @Nullable Instant startInstant;

    private InfoProcessHandle(
        long pid,
        ProcessHandle parent,
        boolean alive,
        @Nullable String command,
        @Nullable String commandLine,
        @Nullable Instant startInstant) {
      this.pid = pid;
      this.parent = parent;
      this.alive = alive;
      this.command = command;
      this.commandLine = commandLine;
      this.startInstant = startInstant;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public Info info() {
      return new Info() {
        @Override
        public Optional<String> command() {
          return Optional.ofNullable(command);
        }

        @Override
        public Optional<String> commandLine() {
          return Optional.ofNullable(commandLine);
        }

        @Override
        public Optional<String[]> arguments() {
          return Optional.empty();
        }

        @Override
        public Optional<Instant> startInstant() {
          return Optional.ofNullable(startInstant);
        }

        @Override
        public Optional<Duration> totalCpuDuration() {
          return Optional.empty();
        }

        @Override
        public Optional<String> user() {
          return Optional.empty();
        }
      };
    }

    @Override
    public CompletableFuture<ProcessHandle> onExit() {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public boolean supportsNormalTermination() {
      return true;
    }

    @Override
    public boolean destroy() {
      return false;
    }

    @Override
    public boolean destroyForcibly() {
      return false;
    }

    @Override
    public boolean isAlive() {
      return alive;
    }

    @Override
    public Optional<ProcessHandle> parent() {
      return Optional.ofNullable(parent);
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> children() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> descendants() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public int compareTo(ProcessHandle other) {
      return Long.compare(pid, other.pid());
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof ProcessHandle handle && pid == handle.pid();
    }

    @Override
    public int hashCode() {
      return Long.hashCode(pid);
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class FadingProcessHandle implements ProcessHandle {
    private final long pid;
    private final AtomicInteger remainingAliveChecks;

    private FadingProcessHandle(long pid, int aliveChecksBeforeExit) {
      this.pid = pid;
      this.remainingAliveChecks = new AtomicInteger(aliveChecksBeforeExit);
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public Info info() {
      return new Info() {
        @Override
        public java.util.Optional<String> command() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> commandLine() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String[]> arguments() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Instant> startInstant() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Duration> totalCpuDuration() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> user() {
          return java.util.Optional.empty();
        }
      };
    }

    @Override
    public CompletableFuture<ProcessHandle> onExit() {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public boolean supportsNormalTermination() {
      return true;
    }

    @Override
    public boolean destroy() {
      return true;
    }

    @Override
    public boolean destroyForcibly() {
      return true;
    }

    @Override
    public boolean isAlive() {
      int checksRemaining = remainingAliveChecks.getAndUpdate(current -> Math.max(0, current - 1));
      return checksRemaining > 0;
    }

    @Override
    public java.util.Optional<ProcessHandle> parent() {
      return java.util.Optional.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> children() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> descendants() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public int compareTo(ProcessHandle other) {
      return Long.compare(pid, other.pid());
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof ProcessHandle handle && pid == handle.pid();
    }

    @Override
    public int hashCode() {
      return Long.hashCode(pid);
    }
  }

  private static final class ControlledProcessHandle implements ProcessHandle {
    private final long pid;
    private final AtomicBoolean alive = new AtomicBoolean(true);

    private ControlledProcessHandle(long pid) {
      this.pid = pid;
    }

    private void markExited() {
      alive.set(false);
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public Info info() {
      return new Info() {
        @Override
        public java.util.Optional<String> command() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> commandLine() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String[]> arguments() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Instant> startInstant() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Duration> totalCpuDuration() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> user() {
          return java.util.Optional.empty();
        }
      };
    }

    @Override
    public CompletableFuture<ProcessHandle> onExit() {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public boolean supportsNormalTermination() {
      return true;
    }

    @Override
    public boolean destroy() {
      return true;
    }

    @Override
    public boolean destroyForcibly() {
      return true;
    }

    @Override
    public boolean isAlive() {
      return alive.get();
    }

    @Override
    public java.util.Optional<ProcessHandle> parent() {
      return java.util.Optional.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> children() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> descendants() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public int compareTo(ProcessHandle other) {
      return Long.compare(pid, other.pid());
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof ProcessHandle handle && pid == handle.pid();
    }

    @Override
    public int hashCode() {
      return Long.hashCode(pid);
    }
  }

  private record ExitedProcessHandle(long pid) implements ProcessHandle {
    @Override
    public Info info() {
      return new Info() {
        @Override
        public java.util.Optional<String> command() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> commandLine() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String[]> arguments() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Instant> startInstant() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Duration> totalCpuDuration() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> user() {
          return java.util.Optional.empty();
        }
      };
    }

    @Override
    public CompletableFuture<ProcessHandle> onExit() {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public boolean supportsNormalTermination() {
      return true;
    }

    @Override
    public boolean destroy() {
      return true;
    }

    @Override
    public boolean destroyForcibly() {
      return true;
    }

    @Override
    public boolean isAlive() {
      return false;
    }

    @Override
    public java.util.Optional<ProcessHandle> parent() {
      return java.util.Optional.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> children() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> descendants() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public int compareTo(ProcessHandle other) {
      return Long.compare(pid, other.pid());
    }
  }
}
