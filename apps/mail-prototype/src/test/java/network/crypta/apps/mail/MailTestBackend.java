package network.crypta.apps.mail;

import java.io.IOException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.crypt.mail.MailWire;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appdata.AppDataStoreConfig;
import network.crypta.platform.api.appdata.FileAppDataStore;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppVaultException;
import network.crypta.platform.appvault.AppVaultService;

/** Real independent vault and app-data service with a synthetic shared transport adapter. */
final class MailTestBackend implements MailBackend {
  static final String APP = "mail-prototype";
  final AppVaultService vault;
  final Path dataset;
  final AppDataService data;
  final Map<String, byte[]> network;
  final Map<String, String> inserted = new LinkedHashMap<>();
  final List<byte[]> insertionBytes = new ArrayList<>();
  byte[] latestSigned;
  volatile boolean failInsertAfterCommit;
  volatile boolean failNextStore;
  int fetches;

  MailTestBackend(Path vaultRoot, Path dataset, Map<String, byte[]> network) throws IOException {
    this.vault = AppVaultService.open(vaultRoot);
    this.dataset = dataset;
    this.data =
        new AppDataService(new FileAppDataStore(dataset), null, AppDataStoreConfig.defaults());
    this.network = network;
  }

  @Override
  public synchronized Map<String, Object> request(
      String method, String path, Map<String, String> p) {
    try {
      if (path.equals("/app-vault/identities")) {
        vault.requireMailIdentityAuthority(APP);
        return Map.of(
            "identities",
            vault.listIdentitiesForApp(APP).stream().map(MailTestBackend::identity).toList());
      }
      if (path.startsWith("/app-vault/identities/")) {
        return Map.of(
            "identity",
            identity(vault.getIdentityForApp(APP, path.substring(path.lastIndexOf('/') + 1))));
      }
      if (path.startsWith("/mail/")) return Map.of("mail", crypto(path.substring(6), p));
      if (path.startsWith("/app-data/records/") && method.equals("GET")) {
        String[] parts = path.split("/");
        return Map.of("record", data.getRecord(APP, parts[3], parts[4]));
      }
      if (path.equals("/app-data/records") && method.equals("POST")) {
        if (failNextStore) {
          failNextStore = false;
          throw new MailFailure("store-unavailable");
        }
        Map<String, List<String>> parameters = new LinkedHashMap<>();
        p.forEach((key, value) -> parameters.put(key, List.of(value)));
        return Map.of("record", data.putRecord(APP, parameters));
      }
      return switch (path) {
        case "/queue/app-document-status" -> {
          String reference = inserted.get(p.get("identifier"));
          yield reference == null
              ? Map.of("state", "missing")
              : Map.of("state", "inserted", "reference", reference);
        }
        case "/queue/inserts/app-document" -> {
          if (!"CHK@".equals(p.get("insertUri"))) throw new AssertionError("Non-CHK insertion");
          byte[] bytes = java.util.Base64.getDecoder().decode(p.get("documentBase64"));
          var outer = MailWire.decode(bytes, 65536);
          if (!"crypta.mail.envelope.v1".equals(outer.get("profile")))
            throw new AssertionError("Non-ciphertext network insertion");
          insertionBytes.add(bytes.clone());
          String reference = addEnvelope(bytes);
          inserted.put(p.get("identifier"), reference);
          if (failInsertAfterCommit) {
            failInsertAfterCommit = false;
            throw new MailFailure("network-unavailable");
          }
          yield Map.of("queued", true);
        }
        case "/content/fetch" -> {
          fetches++;
          byte[] bytes = network.get(p.get("uri"));
          if (bytes == null) throw new MailFailure("network-unavailable");
          yield Map.of("contentBase64", MailWire.base64(bytes));
        }
        case "/queue/restart" -> Map.of("restarted", true);
        default ->
            throw new AssertionError("Unexpected test platform route: " + method + " " + path);
      };
    } catch (AppVaultException failure) {
      throw new MailFailure(
          failure.errorCode().equals("mail_operation_rejected") ? "invalid" : "key-unavailable");
    } catch (PlatformApiException failure) {
      throw new MailFailure(failure.statusCode() == 404 ? "not-found" : failure.errorCode());
    }
  }

  String addEnvelope(byte[] bytes) {
    String digest = hash(bytes);
    String reference =
        "CHK@" + digest.substring(0, 43) + "," + "A".repeat(43) + ",AAICAAI/mail.json";
    network.put(reference, bytes.clone());
    return reference;
  }

  Map<String, String> privateState() {
    var outer = MailWire.decode(storedBytes(), 262144);
    byte[] plain =
        vault.openStorage(
            APP,
            outer.get("storageId"),
            java.util.Base64.getDecoder().decode(outer.get("envelope")));
    return MailWire.decode(plain, 131072);
  }

  private Map<String, Object> crypto(String action, Map<String, String> p) {
    if (action.equals("create-identity")) {
      return identity(vault.createMailIdentity(APP, AppIdentityKind.fromJsonValue(p.get("kind"))));
    }
    String id = p.get("identityId");
    byte[] bytes = java.util.Base64.getDecoder().decode(p.get("payloadBase64"));
    byte[] result =
        switch (action) {
          case "sign" -> vault.signMail(APP, id, bytes);
          case "open" -> vault.openMail(APP, id, bytes);
          case "seal-storage" -> vault.sealStorage(APP, id, bytes);
          case "open-storage" -> vault.openStorage(APP, id, bytes);
          default -> throw new AssertionError("Unknown crypto action");
        };
    if (action.equals("sign")
        && MailWire.MESSAGE.equals(MailWire.decode(bytes, 32768).get("profile"))) {
      latestSigned = result.clone();
    }
    return Map.of("payloadBase64", MailWire.base64(result));
  }

  private static Map<String, Object> identity(AppIdentityRecord identity) {
    return Map.of(
        "identityId",
        identity.identityId(),
        "kind",
        identity.kind().jsonValue(),
        "fingerprint",
        identity.fingerprint(),
        "publicSummary",
        identity.publicSummary());
  }

  byte[] storedBytes() {
    return java.util.Base64.getDecoder()
        .decode((String) data.getRecord(APP, "mail-state", "dataset").get("valueBase64"));
  }

  private static String hash(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException impossible) {
      throw new AssertionError(impossible);
    }
  }
}
