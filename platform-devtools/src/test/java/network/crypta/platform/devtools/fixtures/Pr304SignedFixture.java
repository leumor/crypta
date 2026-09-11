package network.crypta.platform.devtools.fixtures;

// Test-only isolated signing authority. Never packaged or used by a production verifier.
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import network.crypta.platform.appcatalog.AppCatalogSigner;
import network.crypta.platform.appcatalog.AppSubmissionMaintainer;
import network.crypta.platform.appcatalog.AppSubmissionPackageWriter;
import network.crypta.platform.appcatalog.AppSubmissionSourceReference;
import network.crypta.platform.appcatalog.AppSubmissionType;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.devtools.CryptaAppCli;
import picocli.CommandLine;

public final class Pr304SignedFixture {
  private static void cli(String... args) {
    var output = new StringWriter();
    var command = new CommandLine(new CryptaAppCli());
    command.setOut(new PrintWriter(output));
    command.setErr(new PrintWriter(output));
    if (command.execute(args) != 0)
      throw new IllegalStateException("synthetic fixture CLI rejected: " + output);
  }

  static void main(String[] args) throws Exception {
    Path root = Path.of(args[0]);
    var publisher = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var catalogKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var reviewer = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Files.writeString(
        root.resolve("producer-env.json"),
        "{\"CRYPTAD_APP_SIGNING_KEY_ID\":\"publisher\",\"STABLE_CATALOG_SIGNING_KEY_ID\":\"catalog\","
            + "\"CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64\":\""
            + Base64.getEncoder().encodeToString(publisher.getPublic().getEncoded())
            + "\",\"STABLE_CATALOG_SIGNING_PUBLIC_KEY_BASE64\":\""
            + Base64.getEncoder().encodeToString(catalogKey.getPublic().getEncoded())
            + "\",\"STABLE_CATALOG_SIGNING_PRIVATE_KEY_BASE64\":\""
            + Base64.getEncoder().encodeToString(catalogKey.getPrivate().getEncoded())
            + "\"}");
    for (var entry :
        List.of(
            java.util.Map.entry("publisher", publisher),
            java.util.Map.entry("catalog", catalogKey))) {
      Files.writeString(
          root.resolve(entry.getKey() + "-keys.properties"),
          "trusted.keys.version=1\nkey.0.id="
              + entry.getKey()
              + "\nkey.0.algorithm=Ed25519\nkey.0.public.key.base64="
              + Base64.getEncoder().encodeToString(entry.getValue().getPublic().getEncoded())
              + "\n");
    }
    Files.write(root.resolve("review-private.der"), reviewer.getPrivate().getEncoded());
    Files.writeString(
        root.resolve("reviewer-keys.properties"),
        "trusted.reviewers.version=1\n"
            + "reviewer.1.id=synthetic-review\n"
            + "reviewer.1.algorithm=Ed25519\n"
            + "reviewer.1.public.key.base64="
            + Base64.getEncoder().encodeToString(reviewer.getPublic().getEncoded())
            + "\n"
            + "reviewer.1.display.name=Synthetic Review\n"
            + "reviewer.1.policy.id=synthetic-review-v1\n");
    var stable =
        new ArrayList<>(
            List.of(
                "catalog",
                "create",
                "--catalog-file",
                root.resolve("stable.properties").toString(),
                "--catalog-id",
                "synthetic-stable",
                "--name",
                "Synthetic Stable"));
    for (String id :
        List.of(
            "queue-manager",
            "publisher",
            "site-publisher",
            "profile-publisher",
            "social-inbox",
            "feed-reader",
            "trust-graph",
            "mail-prototype",
            "external-app")) {
      Path app = root.resolve(id);
      cli(
          "init",
          "--dir",
          app.toString(),
          "--app-id",
          id,
          "--name",
          "Synthetic subject",
          "--version",
          "1",
          "--permission",
          "queue.read");
      if (id.equals("mail-prototype")) {
        Path manifest = app.resolve("cryptad-app.properties");
        Files.writeString(
            manifest,
            Files.readString(manifest)
                .replace("api.targetStability=stable", "api.targetStability=experimental")
                .replace(
                    "api.experimentalCapabilitiesAccepted=false",
                    "api.experimentalCapabilitiesAccepted=true"));
      }
      AppBundleSigner.sign(app, "publisher", publisher.getPrivate());
      Path bundle = root.resolve(id + ".zip");
      AppBundlePackager.packageBundle(app, bundle);
      Path descriptor = root.resolve(id + "-entry.properties");
      Files.writeString(
          descriptor,
          "artifact.path="
              + bundle
              + "\nbundle.uri="
              + bundle.toUri()
              + "\nsummary=Synthetic subject\nchannel="
              + (id.equals("mail-prototype") ? "beta" : "stable")
              + "\n");
      if (!id.equals("mail-prototype") && !id.equals("external-app")) {
        stable.addAll(List.of("--entry", descriptor.toString()));
        continue;
      }
      String name = id.equals("mail-prototype") ? "experimental" : "external";
      var command =
          new ArrayList<>(
              List.of(
                  "catalog",
                  "create",
                  "--catalog-file",
                  root.resolve(name + ".properties").toString(),
                  "--catalog-id",
                  "synthetic-" + name,
                  "--name",
                  "Synthetic " + name,
                  "--entry",
                  descriptor.toString()));
      if (id.equals("external-app")) {
        Path receipt = root.resolve("external-review.properties");
        cli(
            "review",
            "sign",
            "--catalog-entry",
            descriptor.toString(),
            "--receipt-file",
            receipt.toString(),
            "--reviewer-key-id",
            "synthetic-review",
            "--reviewer-private-key-file",
            root.resolve("review-private.der").toString(),
            "--policy-id",
            "synthetic-review-v1",
            "--policy-version",
            "1",
            "--status",
            "reviewed",
            "--reviewed-at",
            "2026-05-01T00:00:00Z",
            "--bundle-key-id",
            "publisher");
        command.addAll(List.of("--review-receipt", receipt.toString()));
        Path rationale = root.resolve("rationale.txt");
        Files.writeString(rationale, "queue.read: reads synthetic test requests.\n");
        AppSubmissionPackageWriter.create(
            new AppSubmissionPackageWriter.CreateRequest(
                app,
                root.resolve("submission.zip"),
                AppSubmissionType.NEW_APP,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.of(rationale),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                new AppSubmissionMaintainer(
                    "Synthetic maintainer", "mailto:maintainer@example.invalid"),
                new AppSubmissionSourceReference(
                    URI.create("https://example.invalid/repository"), Optional.empty()),
                true,
                false));
      }
      cli(command.toArray(String[]::new));
      AppCatalogSigner.sign(root.resolve(name + ".properties"), "catalog", catalogKey.getPrivate());
      Files.move(root.resolve("cryptad-app-catalog.signature"), root.resolve(name + ".signature"));
    }
    cli(stable.toArray(String[]::new));
    AppCatalogSigner.sign(root.resolve("stable.properties"), "catalog", catalogKey.getPrivate());
    Files.move(root.resolve("cryptad-app-catalog.signature"), root.resolve("stable.signature"));
    Files.delete(root.resolve("review-private.der"));
  }
}
