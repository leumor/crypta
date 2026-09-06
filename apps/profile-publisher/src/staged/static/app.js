(function () {
  "use strict";

  const appId = "profile-publisher";
  const profileDocumentFormat = CryptaPlatform.contentFormats.profileDocument;
  const maxRecentActions = 5;
  const maxDisplayTextLength = 240;
  const maxProfileTextLength = 512;
  const maxProfileBioLength = 4096;
  const maxContentUriLength = 512;
  const maxDocumentPreviewLength = 8192;
  const maxQueueRows = 8;
  const dataNamespace = "profile-draft";
  const dataStateKey = "publisher-state";
  const dataSchemaVersion = 1;
  const durableSaveDelayMs = 150;
  let durableSaveInFlight = false;
  let durableSaveQueued = false;
  let durableSaveTimer = 0;
  const state = {
    draft: {},
    grants: [],
    identities: [],
    lastPublishedProfileUri: "",
    recentActions: [],
    selectedIdentityId: "",
    signedDocument: null,
    uploadQueueReversed: false,
    uploadQueueSortBy: null,
  };

  const elements = {
    documentPreview: document.getElementById("document-preview"),
    grantList: document.getElementById("grant-list"),
    identityForm: document.getElementById("identity-form"),
    identitySelect: document.getElementById("identity-select"),
    identitySummary: document.getElementById("identity-summary"),
    previewButton: document.getElementById("preview-button"),
    profileForm: document.getElementById("profile-form"),
    publishForm: document.getElementById("publish-form"),
    queuePreview: document.getElementById("queue-preview"),
    recentActions: document.getElementById("recent-actions"),
    refreshIdentitiesButton: document.getElementById("refresh-identities-button"),
    refreshQueueButton: document.getElementById("refresh-queue-button"),
    requestGrantButton: document.getElementById("request-grant-button"),
    secondaryRefreshQueueButton: document.getElementById("secondary-refresh-queue-button"),
    signButton: document.getElementById("sign-button"),
    status: document.getElementById("status"),
  };

  document.addEventListener("DOMContentLoaded", start);

  async function start() {
    bindControls();
    initializePublishForm();
    syncDraftFromForm();
    try {
      await CryptaPlatform.bootstrap.load({ appId });
      await loadDurableState();
      restoreDraftToForm();
      await Promise.all([refreshIdentities({ silent: true }), refreshUploadQueue({ silent: true })]);
      renderDocumentPreview(buildUnsignedProfilePreview());
      setStatus("Profile Publisher is ready.");
    } catch (error) {
      setStatus(safeErrorMessage(error), "error");
    }
  }

  function bindControls() {
    elements.identityForm.addEventListener("submit", createIdentity);
    elements.identitySelect.addEventListener("change", selectIdentity);
    elements.previewButton.addEventListener("click", previewDocument);
    elements.profileForm.addEventListener("input", updateDraft);
    elements.publishForm.addEventListener("submit", publishDocument);
    elements.refreshIdentitiesButton.addEventListener("click", refreshIdentities);
    elements.refreshQueueButton.addEventListener("click", refreshUploadQueue);
    elements.requestGrantButton.addEventListener("click", requestSelectedGrant);
    elements.secondaryRefreshQueueButton.addEventListener("click", refreshUploadQueue);
    elements.signButton.addEventListener("click", signPreview);
    elements.queuePreview.addEventListener("click", interceptQueueClick);
    elements.queuePreview.addEventListener("submit", interceptQueueSubmit);
  }

  async function refreshIdentities(options) {
    const refreshOptions = options || {};
    try {
      if (!refreshOptions.silent) {
        setStatus("Loading profile identities...");
      }
      const identities = await CryptaPlatform.vault.identities.list();
      const grants = await CryptaPlatform.vault.grants.list();
      state.identities = normalizeIdentityList(identities);
      state.grants = normalizeGrantList(grants);
      if (!identityById(state.selectedIdentityId) && state.identities.length > 0) {
        setSelectedIdentityId(identityId(state.identities[0]));
      }
      renderIdentities();
      renderGrants();
      if (!refreshOptions.silent) {
        setStatus(`Loaded ${state.identities.length} profile identity record(s).`, "success");
      }
    } catch (error) {
      state.identities = [];
      state.grants = [];
      renderIdentities();
      renderGrants();
      if (!refreshOptions.silent) {
        setStatus(safeErrorMessage(error), "error");
      }
    }
  }

  async function createIdentity(event) {
    event.preventDefault();
    const label = fieldValue(elements.identityForm, "identityLabel") || "Profile Publisher identity";
    try {
      const data = await CryptaPlatform.vault.identities.create({
        label,
        scopes: ["metadata.read", "sign.domain-separated"],
      });
      const identity = data.identity || data;
      setSelectedIdentityId(identityId(identity));
      recordRecentAction("Identity", state.selectedIdentityId || label, "created");
      await refreshIdentities({ silent: true });
      setStatus("Profile identity created.", "success");
    } catch (error) {
      setStatus(safeErrorMessage(error), "error");
    }
  }

  async function requestSelectedGrant() {
    const identityIdValue = selectedIdentityId();
    if (!identityIdValue) {
      setStatus("Select an identity before requesting a grant.", "error");
      return;
    }
    try {
      const request = await CryptaPlatform.vault.grants.request({
        identityId: identityIdValue,
        scopes: ["metadata.read", "sign.domain-separated"],
        reason: "Sign Profile Publisher app documents.",
      });
      renderGrantRequest(request.grantRequest || request);
      recordRecentAction("Grant", identityIdValue, "operator review requested");
      setStatus("Identity grant request prepared for operator review.", "success");
    } catch (error) {
      setStatus(safeErrorMessage(error), "error");
    }
  }

  function selectIdentity() {
    setSelectedIdentityId(elements.identitySelect.value);
    renderSelectedIdentity();
    renderDocumentPreview(buildUnsignedProfilePreview());
    persistDurableState();
  }

  function updateDraft() {
    syncDraftFromForm();
    state.signedDocument = null;
    renderDocumentPreview(buildUnsignedProfilePreview());
    persistDurableState();
  }

  function previewDocument() {
    syncDraftFromForm();
    state.signedDocument = null;
    renderDocumentPreview(buildUnsignedProfilePreview());
    setStatus("Profile app-document preview refreshed.");
  }

  async function signPreview() {
    if (!selectedIdentityId()) {
      setStatus("Select an identity before signing the profile preview.", "error");
      return;
    }
    syncDraftFromForm();
    try {
      state.signedDocument = await createSignedProfileDocument();
      renderDocumentPreview(state.signedDocument);
      recordRecentAction("Signature", selectedIdentityId(), "signed preview");
      setStatus("Profile preview signed.", "success");
    } catch (error) {
      renderDocumentPreview(buildUnsignedProfilePreview());
      setStatus(safeErrorMessage(error), "error");
    }
  }

  async function publishDocument(event) {
    event.preventDefault();
    if (!selectedIdentityId()) {
      setStatus("Select an identity before publishing the profile document.", "error");
      return;
    }
    syncDraftFromForm();
    try {
      const documentData =
        cachedSignedDocumentForSelectedIdentity() || (await createSignedProfileDocument());
      state.signedDocument = documentData;
      renderDocumentPreview(documentData);
      const result = await CryptaPlatform.content.insertAppDocument(buildPublishOptions(documentData));
      renderPublishResult(result);
      await refreshUploadQueue({ silent: true });
      setStatus("Profile app-document publish queued.", "success");
    } catch (error) {
      setStatus(safeErrorMessage(error), "error");
    }
  }

  async function createSignedProfileDocument() {
    const response = await CryptaPlatform.vault.identities.createProfileDocument(
      selectedIdentityId(),
      buildProfilePayload(),
    );
    return CryptaPlatform.profile.verifyDocument(profileDocumentFromResponse(response));
  }

  function cachedSignedDocumentForSelectedIdentity() {
    const documentData = state.signedDocument;
    if (!documentData || typeof documentData !== "object" || !documentData.identity) {
      return null;
    }
    return identityId(documentData.identity) === selectedIdentityId() ? documentData : null;
  }

  function buildPublishOptions(documentData) {
    const identifierField = elements.publishForm.querySelector('input[name="identifier"]');
    const identifier = fieldValue(elements.publishForm, "identifier") || generatedIdentifier("publish");
    const insertUri = publishInsertUriValue(elements.publishForm, "insertUri");
    if (!insertUri) {
      throw new Error("Insert URI must be a nonblank single-line value.");
    }
    if (identifierField instanceof HTMLInputElement) {
      identifierField.value = identifier;
    }
    return {
      document: documentData,
      insertUri,
      identifier,
      contentType: fieldValue(elements.publishForm, "contentType") || profileDocumentFormat.contentType,
      targetFilename: fieldValue(elements.publishForm, "targetFilename") || profileDocumentFormat.defaultFilename,
    };
  }

  async function refreshUploadQueue(options) {
    const refreshOptions = options || {};
    try {
      if (!refreshOptions.silent) {
        setStatus("Loading upload queue...");
      }
      const snapshot = await CryptaPlatform.queue.snapshot({
        page: "uploads",
        sortBy: state.uploadQueueSortBy,
        reversed: state.uploadQueueReversed,
      });
      renderQueue(snapshot.contentHtml);
      if (!refreshOptions.silent) {
        setStatus(uploadQueueStatusMessage());
      }
    } catch (error) {
      if (refreshOptions.silent) {
        renderQueue("");
      } else {
        setStatus(safeErrorMessage(error), "error");
      }
    }
  }

  function buildUnsignedProfilePreview() {
    return {
      schema: profileDocumentFormat.schema,
      profile: buildProfilePayload(),
      identity: selectedIdentitySummary(),
      signature: null,
    };
  }

  function buildProfilePayload() {
    const payload = {
      displayName: state.draft.displayName || "",
    };
    copyOptional(payload, "bio", state.draft.bio);
    copyOptional(payload, "website", state.draft.website);
    copyOptional(payload, "avatarUri", state.draft.avatarUri);
    copyOptional(payload, "contactUri", state.draft.contactUri);
    if (state.draft.tags.length > 0) {
      payload.tags = state.draft.tags;
    }
    return payload;
  }

  function selectedIdentitySummary() {
    const selectedIdentity = identityById(state.selectedIdentityId);
    if (!selectedIdentity) {
      return null;
    }
    return {
      identityId: identityId(selectedIdentity),
      label: identityLabel(selectedIdentity),
      fingerprint: boundedText(selectedIdentity.fingerprint, maxDisplayTextLength),
      publicSummary: boundedText(selectedIdentity.publicSummary, maxDisplayTextLength),
    };
  }

  function syncDraftFromForm() {
    state.draft = {
      avatarUri: optionalCryptaContentUri(rawFieldValue(elements.profileForm, "avatarUri")),
      bio: boundedText(fieldValue(elements.profileForm, "bio"), maxProfileBioLength),
      contactUri: optionalCryptaContentUri(rawFieldValue(elements.profileForm, "contactUri")),
      displayName: boundedText(fieldValue(elements.profileForm, "displayName"), maxProfileTextLength),
      tags: commaValues(fieldValue(elements.profileForm, "tags")),
      website: optionalProfileWebsite(rawFieldValue(elements.profileForm, "website")),
    };
  }

  function initializePublishForm() {
    const identifier = elements.publishForm.querySelector('input[name="identifier"]');
    const contentType = elements.publishForm.querySelector('input[name="contentType"]');
    const targetFilename = elements.publishForm.querySelector('input[name="targetFilename"]');
    if (identifier instanceof HTMLInputElement && !identifier.value.trim()) {
      identifier.value = generatedIdentifier("publish");
    }
    if (contentType instanceof HTMLInputElement) {
      contentType.value = profileDocumentFormat.contentType;
    }
    if (targetFilename instanceof HTMLInputElement) {
      targetFilename.value = profileDocumentFormat.defaultFilename;
    }
  }

  async function loadDurableState() {
    if (!dataHelpersAvailable()) {
      return;
    }
    try {
      const stored = await CryptaPlatform.data.records.getJson(dataNamespace, dataStateKey);
      if (!stored || stored.schemaVersion !== dataSchemaVersion) {
        return;
      }
      if (stored.draft && typeof stored.draft === "object") {
        state.draft = normalizeStoredDraft(stored.draft);
      }
      state.selectedIdentityId = stringValue(stored.selectedIdentityId);
      state.lastPublishedProfileUri = stringValue(stored.lastPublishedProfileUri);
      if (Array.isArray(stored.recentActions)) {
        state.recentActions = stored.recentActions
          .slice(0, maxRecentActions)
          .map(normalizeRecentAction)
          .filter(Boolean);
        renderRecentActions();
      }
    } catch (error) {
      // First launch or older nodes may not have a saved draft record yet.
    }
  }

  function persistDurableState() {
    if (!dataHelpersAvailable()) {
      return;
    }
    durableSaveQueued = true;
    scheduleDurableStateSave();
  }

  function scheduleDurableStateSave() {
    if (durableSaveInFlight) {
      return;
    }
    if (durableSaveTimer) {
      window.clearTimeout(durableSaveTimer);
    }
    durableSaveTimer = window.setTimeout(() => {
      durableSaveTimer = 0;
      flushDurableStateSaves();
    }, durableSaveDelayMs);
  }

  async function flushDurableStateSaves() {
    if (durableSaveInFlight || !dataHelpersAvailable()) {
      return;
    }
    durableSaveInFlight = true;
    try {
      while (durableSaveQueued) {
        durableSaveQueued = false;
        await writeDurableStateSnapshot();
      }
    } finally {
      durableSaveInFlight = false;
      if (durableSaveQueued) {
        scheduleDurableStateSave();
      }
    }
  }

  async function writeDurableStateSnapshot() {
    try {
      await CryptaPlatform.data.records.putJson({
        namespace: dataNamespace,
        key: dataStateKey,
        schemaVersion: dataSchemaVersion,
        value: durableStateValue(),
      });
    } catch (error) {
      setStatus("Profile draft could not be saved.", "error");
    }
  }

  function durableStateValue() {
    return {
      schemaVersion: dataSchemaVersion,
      draft: normalizeStoredDraft(state.draft),
      selectedIdentityId: boundedText(state.selectedIdentityId, maxProfileTextLength),
      lastPublishedProfileUri: optionalCryptaContentUri(state.lastPublishedProfileUri),
      recentActions: state.recentActions
        .slice(0, maxRecentActions)
        .map(normalizeRecentAction)
        .filter(Boolean),
    };
  }

  function dataHelpersAvailable() {
    return (
      CryptaPlatform.data &&
      CryptaPlatform.data.records &&
      typeof CryptaPlatform.data.records.getJson === "function" &&
      typeof CryptaPlatform.data.records.putJson === "function"
    );
  }

  function normalizeStoredDraft(draft) {
    return {
      avatarUri: optionalCryptaContentUri(draft.avatarUri),
      bio: boundedText(draft.bio, maxProfileBioLength),
      contactUri: optionalCryptaContentUri(draft.contactUri),
      displayName: boundedText(draft.displayName, maxProfileTextLength),
      tags: Array.isArray(draft.tags)
        ? draft.tags.map((tag) => boundedText(tag, 32)).filter(Boolean).slice(0, 12)
        : [],
      website: optionalProfileWebsite(draft.website),
    };
  }

  function normalizeRecentAction(action) {
    if (!action || typeof action !== "object") {
      return null;
    }
    return {
      at: boundedText(action.at, maxDisplayTextLength),
      kind: boundedText(action.kind, maxDisplayTextLength),
      outcome: boundedText(action.outcome, maxDisplayTextLength),
      subject: boundedText(action.subject, maxDisplayTextLength),
    };
  }

  function restoreDraftToForm() {
    setFieldValue(elements.profileForm, "avatarUri", state.draft.avatarUri);
    setFieldValue(elements.profileForm, "bio", state.draft.bio);
    setFieldValue(elements.profileForm, "contactUri", state.draft.contactUri);
    setFieldValue(elements.profileForm, "displayName", state.draft.displayName);
    setFieldValue(elements.profileForm, "tags", state.draft.tags.join(", "));
    setFieldValue(elements.profileForm, "website", state.draft.website);
  }

  function setFieldValue(form, name, value) {
    const field = form.querySelector(`[name="${name}"]`);
    if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) {
      field.value = stringValue(value);
    }
  }

  function renderIdentities() {
    elements.identitySelect.replaceChildren();
    if (state.identities.length === 0) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No granted identities";
      elements.identitySelect.append(option);
      elements.identitySelect.disabled = true;
      setSelectedIdentityId("");
      renderSelectedIdentity();
      return;
    }
    elements.identitySelect.disabled = false;
    for (const identity of state.identities) {
      const option = document.createElement("option");
      option.value = identityId(identity);
      option.textContent = identityLabel(identity);
      option.selected = option.value === state.selectedIdentityId;
      elements.identitySelect.append(option);
    }
    renderSelectedIdentity();
  }

  function setSelectedIdentityId(value) {
    const nextIdentityId = stringValue(value);
    if (state.selectedIdentityId !== nextIdentityId) {
      state.selectedIdentityId = nextIdentityId;
      state.signedDocument = null;
    }
  }

  function renderSelectedIdentity() {
    const identity = identityById(state.selectedIdentityId);
    if (!identity) {
      elements.identitySummary.replaceChildren(
        text("p", "cr-empty", "No granted identity metadata is available."),
      );
      return;
    }
    const panel = document.createElement("div");
    panel.className = "summary";
    panel.append(
      summaryRow("Identity", identityLabel(identity)),
      summaryRow("Identifier", identityId(identity)),
      summaryRow("Kind", identity.kind),
      summaryRow("Fingerprint", identity.fingerprint),
    );
    elements.identitySummary.replaceChildren(panel);
  }

  function renderGrants() {
    if (state.grants.length === 0) {
      elements.grantList.replaceChildren(text("p", "cr-empty", "No visible grants returned."));
      return;
    }
    const list = document.createElement("div");
    list.className = "grant-list";
    for (const grant of state.grants) {
      const item = document.createElement("div");
      item.className = "grant-item";
      item.append(
        summaryRow("Grant identity", grant.identityId || grant.id),
        summaryRow("Scopes", Array.isArray(grant.scopes) ? grant.scopes.join(", ") : grant.scopes),
        summaryRow("Status", grant.status),
      );
      list.append(item);
    }
    elements.grantList.replaceChildren(list);
  }

  function renderGrantRequest(request) {
    const panel = document.createElement("div");
    panel.className = "grant-list";
    const item = document.createElement("div");
    item.className = "grant-item";
    item.append(
      summaryRow("Grant request", request.status),
      summaryRow("Identity", request.identityId),
      summaryRow("Scopes", Array.isArray(request.scopes) ? request.scopes.join(", ") : request.scopes),
    );
    panel.append(item);
    elements.grantList.replaceChildren(panel);
  }

  function renderDocumentPreview(documentData) {
    elements.documentPreview.textContent = boundedText(
      JSON.stringify(profileDocumentPreviewSummary(documentData), null, 2),
      maxDocumentPreviewLength,
    );
  }

  function profileDocumentPreviewSummary(documentData) {
    const profile = documentData && typeof documentData === "object" ? documentData.profile || {} : {};
    const identity = documentData && typeof documentData === "object" ? documentData.identity : null;
    return {
      schema: profileDocumentFormat.schema,
      contentType: profileDocumentFormat.contentType,
      profileVersion: profileDocumentFormat.majorVersion,
      maxDocumentBytes: profileDocumentFormat.maxDocumentBytes,
      displayName: boundedText(profile.displayName || "", maxDisplayTextLength),
      hasBio: Boolean(profile.bio),
      hasWebsite: Boolean(profile.website),
      hasAvatar: Boolean(profile.avatarUri),
      hasContact: Boolean(profile.contactUri),
      tagCount: Array.isArray(profile.tags) ? profile.tags.length : 0,
      identitySummary: summarizeIdentityForPreview(identity),
      signature: documentData && documentData.signature ? "present" : "not present",
      signingDomain: profileDocumentFormat.signingDomain,
      unknownFields: profileDocumentFormat.unknownFieldPolicy,
      redaction: "profile summary only; raw signature and vault identity material omitted",
    };
  }

  function summarizeIdentityForPreview(identity) {
    if (!identity || typeof identity !== "object") {
      return "not selected";
    }
    const identifier = identityId(identity);
    if (!identifier) {
      return "selected";
    }
    return `${identifier.slice(0, 12)}...`;
  }

  function renderPublishResult(data) {
    state.lastPublishedProfileUri = optionalCryptaContentUri(
      data && (data.profileUri || data.finalUri || data.uri || data.targetUri || data.requestUri),
    );
    recordRecentAction(
      "Publish",
      boundedText(data && data.identifier, maxDisplayTextLength),
      data && (data.outcome || data.status) || "queued",
    );
  }

  function recordRecentAction(kind, subject, outcome) {
    state.recentActions.unshift({
      at: new Date().toLocaleTimeString(),
      kind: boundedText(kind, maxDisplayTextLength),
      outcome: boundedText(outcome, maxDisplayTextLength),
      subject: boundedText(subject, maxDisplayTextLength),
    });
    state.recentActions = state.recentActions.slice(0, maxRecentActions);
    renderRecentActions();
    persistDurableState();
  }

  function renderRecentActions() {
    if (state.recentActions.length === 0) {
      elements.recentActions.replaceChildren(
        text("p", "cr-empty", "Recent publish actions appear after preview or publish work."),
      );
      return;
    }
    const list = document.createElement("div");
    list.className = "recent-list";
    for (const action of state.recentActions) {
      const item = document.createElement("div");
      item.className = "recent-item";
      item.append(
        summaryRow("When", action.at),
        summaryRow("Action", action.kind),
        summaryRow("Subject", action.subject),
        summaryRow("Outcome", action.outcome),
      );
      list.append(item);
    }
    elements.recentActions.replaceChildren(list);
  }

  function renderQueue(contentHtml) {
    const container = document.createElement("div");
    container.className = "queue-content";
    const queueModel = queueModelFromHtml(contentHtml);
    const sortControls = renderQueueSortControls(queueModel.sortLinks);
    if (sortControls) {
      container.append(sortControls);
    }
    const rows = queueModel.rows.slice(0, maxQueueRows);
    if (rows.length === 0) {
      container.append(text("p", "cr-empty", "No upload queue content was returned."));
      elements.queuePreview.replaceChildren(container);
      return;
    }
    for (const row of rows) {
      const item = document.createElement("div");
      item.className = "queue-item";
      item.append(summaryRow("Item", row.label), summaryRow("Status", row.detail));
      container.append(item);
    }
    elements.queuePreview.replaceChildren(container);
  }

  function queueModelFromHtml(contentHtml) {
    const html = typeof contentHtml === "string" ? contentHtml : "";
    if (!html.trim()) {
      return { rows: [], sortLinks: [] };
    }
    const documentValue = new DOMParser().parseFromString(html, "text/html");
    removeUnsafeParsedNodes(documentValue);
    return {
      rows: queueRowsFromDocument(documentValue),
      sortLinks: queueSortLinksFromDocument(documentValue),
    };
  }

  function queueRowsFromHtml(contentHtml) {
    return queueModelFromHtml(contentHtml).rows;
  }

  function queueRowsFromDocument(documentValue) {
    if (!documentValue || !documentValue.body) {
      return [];
    }
    const tableRows = Array.from(documentValue.querySelectorAll("tr"))
      .map(queueRowFromTableRow)
      .filter(Boolean);
    if (tableRows.length > 0) {
      return tableRows;
    }
    const listRows = queueRowsFromNodes(documentValue.querySelectorAll("li"), "Queue item");
    if (listRows.length > 0) {
      return listRows;
    }
    const paragraphRows = queueRowsFromNodes(documentValue.querySelectorAll("p"), "Queue status");
    if (paragraphRows.length > 0) {
      return paragraphRows;
    }
    const bodyText = compactQueueText(documentValue.body && documentValue.body.textContent);
    return bodyText ? [{ label: "Queue snapshot", detail: bodyText }] : [];
  }

  function queueSortLinksFromDocument(documentValue) {
    const seen = new Set();
    return Array.from(documentValue.querySelectorAll("a[href]"))
      .map(queueSortLinkFromAnchor)
      .filter(Boolean)
      .filter((link) => {
        if (seen.has(link.href)) {
          return false;
        }
        seen.add(link.href);
        return true;
      })
      .slice(0, 8);
  }

  function queueSortLinkFromAnchor(anchor) {
    const sortLink = safeQueueSortLink(anchor.getAttribute("href") || "");
    if (!sortLink) {
      return null;
    }
    return {
      href: sortLink.href,
      label:
        boundedText(anchor.textContent, 48) ||
        queueSortLabel(sortLink.sortBy, sortLink.reversed),
      reversed: sortLink.reversed,
      sortBy: sortLink.sortBy,
    };
  }

  function safeQueueSortLink(rawHref) {
    if (typeof rawHref !== "string" || !rawHref.startsWith("?")) {
      return null;
    }
    const params = new URLSearchParams(rawHref.slice(1));
    const sortBy = params.get("sortBy");
    if (!isSafeQueueSortKey(sortBy)) {
      return null;
    }
    const reversed = params.get("reversed") === "true" || params.has("reversed");
    const next = new URLSearchParams();
    next.set("sortBy", sortBy);
    if (reversed) {
      next.set("reversed", "true");
    }
    return { href: `?${next.toString()}`, reversed, sortBy };
  }

  function isSafeQueueSortKey(value) {
    return typeof value === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(value);
  }

  function queueSortLabel(sortBy, reversed) {
    const label = boundedText(sortBy.replace(/[_.-]+/g, " "), 48) || "queue";
    return `Sort by ${label}${reversed ? " descending" : ""}`;
  }

  function renderQueueSortControls(sortLinks) {
    if (!Array.isArray(sortLinks) || sortLinks.length === 0) {
      return null;
    }
    const controls = document.createElement("div");
    controls.className = "queue-sort-controls";
    controls.append(text("span", "cr-label", "Sort"));
    for (const link of sortLinks) {
      const anchor = document.createElement("a");
      anchor.className = "queue-sort-link";
      anchor.setAttribute("href", link.href);
      anchor.textContent = link.label;
      if (
        state.uploadQueueSortBy === link.sortBy &&
        state.uploadQueueReversed === link.reversed
      ) {
        anchor.setAttribute("aria-current", "true");
      }
      controls.append(anchor);
    }
    return controls;
  }

  function queueRowFromTableRow(row) {
    const cells = Array.from(row.querySelectorAll("td")).map((cell) =>
      compactQueueText(cell.textContent),
    );
    const visibleCells = cells.filter(Boolean);
    if (visibleCells.length === 0) {
      return null;
    }
    return {
      label: visibleCells[0] || "Queue item",
      detail: visibleCells.slice(1).join(" | ") || visibleCells[0],
    };
  }

  function queueRowsFromNodes(nodes, label) {
    return Array.from(nodes)
      .map((node) => compactQueueText(node.textContent))
      .filter(Boolean)
      .map((detail) => ({ label, detail }));
  }

  function removeUnsafeParsedNodes(documentValue) {
    documentValue
      .querySelectorAll(unsafeParsedElementSelector())
      .forEach((node) => node.remove());
    documentValue.querySelectorAll("*").forEach((element) => {
      Array.from(element.attributes).forEach((attribute) => {
        const name = attribute.name.toLowerCase();
        if (name.startsWith("on") || name === "style" || name === "srcdoc") {
          element.removeAttribute(attribute.name);
        }
      });
    });
  }

  function unsafeParsedElementSelector() {
    return "script, style, template, noscript, iframe, frame, frameset, object, embed, link, meta, base, svg, math";
  }

  function interceptQueueClick(event) {
    const target = event.target instanceof Element ? event.target : null;
    const anchor = target ? target.closest("a") : null;
    if (!anchor || !elements.queuePreview.contains(anchor)) {
      return;
    }
    if (updateUploadQueueSort(anchor.getAttribute("href") || "")) {
      event.preventDefault();
      return;
    }
    event.preventDefault();
    setStatus("Open Queue Manager for detailed queue actions.", "error");
  }

  function interceptQueueSubmit(event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    event.preventDefault();
    setStatus("Open Queue Manager for detailed queue actions.", "error");
  }

  function updateUploadQueueSort(rawHref) {
    if (typeof rawHref !== "string" || !rawHref.startsWith("?")) {
      return false;
    }
    const params = new URLSearchParams(rawHref.slice(1));
    if (!params.has("sortBy")) {
      return false;
    }
    state.uploadQueueSortBy = params.get("sortBy");
    state.uploadQueueReversed = params.get("reversed") === "true" || params.has("reversed");
    refreshUploadQueue();
    return true;
  }

  function profileDocumentFromResponse(response) {
    if (response && response.profileDocument && typeof response.profileDocument === "object") {
      return response.profileDocument;
    }
    return response;
  }

  function normalizeIdentityList(data) {
    if (Array.isArray(data)) {
      return data;
    }
    return data && Array.isArray(data.identities) ? data.identities : [];
  }

  function normalizeGrantList(data) {
    if (Array.isArray(data)) {
      return data;
    }
    return data && Array.isArray(data.grants) ? data.grants : [];
  }

  function selectedIdentityId() {
    return elements.identitySelect.disabled ? "" : state.selectedIdentityId;
  }

  function identityById(id) {
    return state.identities.find((identity) => identityId(identity) === id) || null;
  }

  function identityId(identity) {
    return boundedText(identity.identityId || identity.id, maxProfileTextLength);
  }

  function identityLabel(identity) {
    return (
      boundedText(identity.label || identity.displayName, maxDisplayTextLength) ||
      identityId(identity) ||
      "Profile identity"
    );
  }

  function uploadQueueStatusMessage() {
    if (!state.uploadQueueSortBy) {
      return "Showing upload queue progress.";
    }
    return `Showing upload queue sorted by ${state.uploadQueueSortBy}${
      state.uploadQueueReversed ? " descending" : ""
    }.`;
  }

  function generatedIdentifier(kind) {
    const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
    const random = Math.random().toString(36).slice(2, 8);
    return `profile-publisher-${kind}-${timestamp}-${random}`;
  }

  function fieldValue(form, name) {
    const value = rawFieldValue(form, name);
    const field = form.querySelector(`[name="${name}"]`);
    return field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement
      ? boundedText(
          value,
          field instanceof HTMLTextAreaElement ? maxProfileBioLength : maxProfileTextLength,
        )
      : "";
  }

  function rawFieldValue(form, name) {
    const field = form.querySelector(`[name="${name}"]`);
    return field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement ? field.value : "";
  }

  function publishInsertUriValue(form, name) {
    const uri = rawFieldValue(form, name).trim();
    if (!uri) {
      return "";
    }
    return unsafePublishUriPattern().test(uri) ? "" : uri;
  }

  function commaValues(value) {
    return stringValue(value)
      .split(",")
      .map((item) => boundedText(item, 32))
      .filter(Boolean);
  }

  function copyOptional(target, name, value) {
    if (typeof value === "string" && value) {
      target[name] = value;
    }
  }

  function summaryRow(label, value) {
    const row = document.createElement("p");
    const key = document.createElement("strong");
    key.textContent = `${label}: `;
    const safeValue = boundedText(value, maxDisplayTextLength);
    row.append(key, document.createTextNode(safeValue || "Unavailable"));
    return row;
  }

  function text(tagName, className, value) {
    const node = document.createElement(tagName);
    node.className = className;
    node.textContent = boundedText(value, maxDisplayTextLength);
    return node;
  }

  function stringValue(value) {
    return value == null ? "" : String(value);
  }

  function boundedText(value, maxLength) {
    const textValue = stringValue(value).trim().replace(unsafeControlPattern(), " ");
    if (textValue.length <= maxLength) {
      return textValue;
    }
    return `${textValue.slice(0, Math.max(0, maxLength - 3))}...`;
  }

  function optionalCryptaContentUri(value) {
    const uri = stringValue(value).trim();
    if (!uri) {
      return "";
    }
    if (uri.length > maxContentUriLength) {
      return "";
    }
    if (unsafeControlPattern().test(uri) || /[\s\\]/.test(uri) || uri.includes("?") || uri.includes("#")) {
      return "";
    }
    const runtimeUri = uri.toLowerCase().startsWith("crypta:") ? uri.slice(7).trim() : uri;
    if (!runtimeUri || runtimeUri.startsWith("/") || runtimeUri.startsWith("\\")) {
      return "";
    }
    const colon = runtimeUri.indexOf(":");
    const at = runtimeUri.indexOf("@");
    if (colon >= 0 && (at < 0 || colon < at)) {
      return "";
    }
    const upper = runtimeUri.toUpperCase();
    return ["CHK", "SSK", "USK", "KSK"].some(
      (kind) => upper.startsWith(`${kind}@`) && runtimeUri.length > kind.length + 1,
    )
      ? uri
      : "";
  }

  function optionalProfileWebsite(value) {
    const website = stringValue(value).trim();
    if (!website) {
      return "";
    }
    if (website.length > maxContentUriLength) {
      return "";
    }
    return unsafeSingleLineControlPattern().test(website) ? "" : website;
  }

  function compactQueueText(value) {
    return boundedText(stringValue(value).replace(/\s+/g, " "), maxDisplayTextLength);
  }

  function unsafeControlPattern() {
    return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
  }

  function unsafeSingleLineControlPattern() {
    return /[\u0000-\u001f\u007f]/;
  }

  function unsafePublishUriPattern() {
    return /[\s\\\u0000-\u001f\u007f]/;
  }

  function safeErrorMessage(error) {
    const fallback = "Profile request failed. Retry the grant or publish action, then use Operator RC Recovery if needed.";
    let message = "";
    try {
      message =
        CryptaPlatform.api && typeof CryptaPlatform.api.errorMessage === "function"
          ? CryptaPlatform.api.errorMessage(error)
          : error && error.message;
    } catch (_) {
      message = "";
    }
    message = stringValue(message).replace(/\s+/g, " ").trim();
    if (!message || sensitiveDiagnosticPattern().test(message)) {
      return fallback;
    }
    return boundedText(message, maxDisplayTextLength);
  }

  function sensitiveDiagnosticPattern() {
    return /(crypta:(?:ssk|usk)@|(?:ssk|usk)@|authorization|bearer|token|private key|identity material|browser session|form password|raw (?:content|message|app data)|signatureBase64|publicKeyBase64|[A-Za-z]:\\|\/(?:home|Users|work|tmp|var)\/)/i;
  }

  function setStatus(message, tone) {
    elements.status.textContent = boundedText(message, maxDisplayTextLength);
    elements.status.className = statusClassName(tone);
  }

  function statusClassName(tone) {
    switch (tone) {
      case "success":
        return "cr-status cr-status--success";
      case "error":
        return "cr-status cr-status--danger";
      default:
        return "cr-status";
    }
  }
})();
