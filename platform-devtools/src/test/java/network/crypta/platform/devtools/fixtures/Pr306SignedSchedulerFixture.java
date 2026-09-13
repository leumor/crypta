package network.crypta.platform.devtools.fixtures;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.util.Base64;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.devtools.CryptaAppCli;
import picocli.CommandLine;

/** Creates one disposable signed subscription experiment; it is never a release cohort member. */
public final class Pr306SignedSchedulerFixture {
  private Pr306SignedSchedulerFixture() {}

  static void main(String[] args) throws Exception {
    Path root = Path.of(args[0]);
    Files.createDirectories(root);
    Path app = root.resolve("feed-reader");
    var output = new StringWriter();
    var command = new CommandLine(new CryptaAppCli());
    command.setOut(new PrintWriter(output));
    command.setErr(new PrintWriter(output));
    int result =
        command.execute(
            "init",
            "--dir",
            app.toString(),
            "--app-id",
            "feed-reader",
            "--name",
            "Synthetic scheduler subject",
            "--version",
            "1",
            "--permission",
            "content.fetch",
            "--permission",
            "content.subscribe");
    if (result != 0) throw new IllegalStateException("scheduler-fixture-init-failed");
    // The actual first-party static UI uses daemon-hosted browser principals. This minimal worker
    // owns no fetched content; its separate OS epoch is still measured to avoid a process-tree sum.
    Files.writeString(app.resolve("bin/start.sh"), "#!/bin/sh\nset -eu\nexec sleep 600\n");
    Path manifest = app.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest)
            .replace("sandbox.mode=none", "sandbox.mode=restricted-process")
            .replace("sandbox.required=false", "sandbox.required=true"));
    var publisher = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Files.writeString(
        root.resolve("publisher-keys.properties"),
        "trusted.keys.version=1\nkey.0.id=synthetic-scheduler\nkey.0.algorithm=Ed25519\n"
            + "key.0.public.key.base64="
            + Base64.getEncoder().encodeToString(publisher.getPublic().getEncoded())
            + "\n");
    AppBundleSigner.sign(app, "synthetic-scheduler", publisher.getPrivate());
    AppBundlePackager.packageBundle(app, root.resolve("feed-reader.zip"));
  }
}
