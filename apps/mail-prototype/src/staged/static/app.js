(() => {
  "use strict";
  let approval = "";
  let renewalToken = "";
  let draftRevision = 0;
  let busy = false;
  const field = (id) => document.getElementById(id).value;
  const invalidate = () => {
    draftRevision++;
    approval = "";
    renewalToken = "";
    document.getElementById("confirm-send").disabled = true;
    document.getElementById("confirm-renew-contact").disabled = true;
  };

  async function invoke(command) {
    if (busy) return;
    const payload = {};
    switch (command) {
      case "import-contact": payload.card = field("card"); break;
      case "approve-contact":
      case "revoke-contact": payload.fingerprint = field("fingerprint"); break;
      case "save-draft":
        payload.fingerprint = field("fingerprint");
        payload.subject = field("subject");
        payload.body = field("body");
        if (new TextEncoder().encode(payload.body).length > 16384) {
          document.getElementById("status").textContent = "Body exceeds 16 KiB UTF-8.";
          return;
        }
        break;
      case "confirm-send":
        if (!approval) return;
        payload.approval = approval;
        break;
      case "confirm-renew-contact":
        if (!renewalToken) return;
        payload.renewalToken = renewalToken;
        break;
      case "import-reference": payload.reference = field("reference"); payload.confirmed = "yes"; break;
      case "retry": payload.operation = field("operation"); break;
      case "read": payload.messageId = field("messageId"); break;
      case "restore": payload.backup = field("backup"); payload.confirmed = "yes"; break;
      default: break;
    }
    if (command !== "preview-send") invalidate();
    const previewRevision = draftRevision;
    busy = true;
    document.getElementById("status").textContent = "Waiting for the Mail worker…";
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), 30000);
    try {
      await CryptaPlatform.bootstrap.load({ appId: "mail-prototype", signal: controller.signal });
      const result = await CryptaPlatform.mail.command(command, payload, { signal: controller.signal });
      document.getElementById("result").textContent = JSON.stringify(result, null, 2);
      const exported = result.card || result.backup || result.reference;
      document.getElementById("export-value").value = typeof exported === "string" ? exported : "";
      if (command === "preview-send" && previewRevision === draftRevision && typeof result.approval === "string") {
        approval = result.approval;
        document.getElementById("confirm-send").disabled = false;
      }
      if (command === "preview-renew-contact" && previewRevision === draftRevision && typeof result.renewalToken === "string") {
        renewalToken = result.renewalToken;
        document.getElementById("confirm-renew-contact").disabled = false;
      }
      if (command === "import-contact" && typeof result.fingerprint === "string") {
        document.getElementById("fingerprint").value = result.fingerprint;
      }
      document.getElementById("status").textContent = "Operation finished. Review the private result.";
    } catch (_) {
      invalidate();
      document.getElementById("status").textContent = "Operation unavailable or failed. Refresh private status before retrying; an insert outcome may be uncertain.";
    } finally {
      clearTimeout(deadline);
      busy = false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-command]").forEach((button) => {
      button.addEventListener("click", () => invoke(button.dataset.command));
    });
    ["fingerprint", "subject", "body", "card"].forEach((id) => {
      document.getElementById(id).addEventListener("input", invalidate);
    });
  });
})();
