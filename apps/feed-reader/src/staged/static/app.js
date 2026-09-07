(function () {
  "use strict";

  const appId = "feed-reader";
  const feedSnapshotFormat = CryptaPlatform.contentFormats.feedSnapshot;
  const rawFeedFetchMaxBytes = 262144;
  const maxSources = 12;
  const maxEntriesPerSnapshot = 20;
  const maxRememberedSnapshots = 12;
  const maxPublishResults = 5;
  const maxDisplayLabelLength = 80;
  const maxFeedTitleLength = 160;
  const maxFeedBodyLength = 1000;
  const maxContentUriLength = 512;
  const maxTagLength = 32;
  const subscriptionPollIntervalSeconds = 5 * 60;
  const dataNamespace = "ui-state";
  const dataStateKey = "reader-state";
  const dataSchemaVersion = 2;

  const state = {
    sources: [],
    subscriptions: [],
    selectedSourceId: "",
    fetchedSnapshots: [],
    publishResults: [],
    uploadQueueSortBy: null,
    uploadQueueReversed: false,
    lastPublisherDraft: {},
  };

  const elements = {
    followStatus: document.getElementById("follow-status"),
    publisherForm: document.getElementById("publisher-form"),
    publishResult: document.getElementById("publish-result"),
    queuePreview: document.getElementById("queue-preview"),
    readerContent: document.getElementById("reader-content"),
    refreshQueueButton: document.getElementById("refresh-queue-button"),
    refreshSelectedButton: document.getElementById("refresh-selected-button"),
    refreshSubscriptionsButton: document.getElementById("refresh-subscriptions-button"),
    secondaryRefreshQueueButton: document.getElementById("secondary-refresh-queue-button"),
    sourceForm: document.getElementById("source-form"),
    sourceList: document.getElementById("source-list"),
    status: document.getElementById("status"),
    subscriptionList: document.getElementById("subscription-list"),
  };

  document.addEventListener("DOMContentLoaded", start);

  async function start() {
    bindControls();
    try {
      await CryptaPlatform.bootstrap.load({ appId });
      await loadDurableState();
      restorePublisherDraft();
      await loadSubscriptions({ silent: true });
      renderSources();
      renderReader();
      await refreshUploadQueue({ silent: true });
    } catch (error) {
      setStatus(safeErrorMessage(error), "error");
    }
  }

  function bindControls() {
    elements.sourceForm.addEventListener("submit", addSource);
    elements.publisherForm.addEventListener("submit", publishSnapshot);
    elements.refreshSelectedButton.addEventListener("click", refreshSelectedSource);
    elements.refreshSubscriptionsButton.addEventListener("click", loadSubscriptions);
    elements.refreshQueueButton.addEventListener("click", refreshUploadQueue);
    elements.secondaryRefreshQueueButton.addEventListener("click", refreshUploadQueue);
  }

  async function addSource(event) {
    event.preventDefault();
    if (state.sources.length >= maxSources) {
      setStatus("Source limit reached for this page.", "error");
      return;
    }
    const source = {
      label: fieldValue(elements.sourceForm, "label"),
      uri: fieldValue(elements.sourceForm, "uri"),
      followUsk: checkboxValue(elements.sourceForm, "followUsk"),
    };
    if (!normalizedCryptaContentUri(source.uri, ["CHK", "SSK", "USK", "KSK"])) {
      setStatus("Feed sources must be CHK@, SSK@, USK@, KSK@, or crypta: content keys.", "error");
      return;
    }
    const added = addSourceToState(source);
    elements.sourceForm.reset();
    if (added.followUsk) {
      await createSubscriptionForSource(added);
    }
    await persistDurableState();
    renderSources();
    renderSubscriptions();
    setStatus(added.subscriptionId ? "Feed source subscribed." : "Feed source added.");
  }

  function addSourceToState(source) {
    const id = generatedId("source");
    const added = {
      id,
      label: boundedText(source.label, maxDisplayLabelLength) || "Untitled feed",
      uri: normalizedCryptaContentUri(source.uri, ["CHK", "SSK", "USK", "KSK"]),
      followUsk: !!source.followUsk,
      subscriptionId: "",
      lastFetchedAt: "",
      lastStatus: "Not fetched",
    };
    state.sources.unshift(added);
    state.selectedSourceId = id;
    return added;
  }

  async function refreshSelectedSource() {
    const source = selectedSource();
    if (!source) {
      setStatus("Select or add a feed source first.", "error");
      return;
    }
    await refreshSource(source, { follow: source.followUsk });
  }

  async function refreshSource(source, options) {
    try {
      setStatus("Fetching feed snapshot...");
      const snapshot = await fetchSourceSnapshot(source, options || {});
      source.lastFetchedAt = new Date().toLocaleTimeString();
      source.lastStatus = "Fetched";
      rememberSnapshot(normalizeSnapshot(source, snapshot));
      await persistDurableState();
      renderSources();
      renderReader();
      setStatus("Feed snapshot fetched.", "success");
    } catch (error) {
      source.lastStatus = safeErrorMessage(error);
      renderSources();
      setStatus(source.lastStatus, "error");
    }
  }

  async function fetchSourceSnapshot(source, options) {
    const subscriptionSummary = options.subscriptionSummary || subscriptionForSource(source);
    const fetchUri = normalizedCryptaContentUri(
      stringValue(subscriptionSummary && subscriptionSummary.lastSeenResolvedUri) || source.uri,
      ["CHK", "SSK", "USK", "KSK"],
    );
    if (!fetchUri) {
      throw new Error("Feed source URI is malformed or unsupported.");
    }
    const request = {
      uri: fetchUri,
      maxBytes: rawFeedFetchMaxBytes,
      timeoutMillis: 30000,
      purpose: options.follow && isUskUri(source.uri) ? "feed-subscription" : "feed-preview",
    };
    if (
      CryptaPlatform.content &&
      typeof CryptaPlatform.content.fetchText === "function"
    ) {
      const response = await CryptaPlatform.content.fetchText(request);
      return snapshotFromTextResponse(source, response);
    }
    if (
      CryptaPlatform.feed &&
      typeof CryptaPlatform.feed.fetchSnapshot === "function"
    ) {
      return CryptaPlatform.feed.fetchSnapshot(request);
    }
    throw new Error("Feed fetch helper is unavailable.");
  }

  async function loadSubscriptions(options) {
    const loadOptions = options || {};
    if (!subscriptionHelpersAvailable()) {
      state.subscriptions = [];
      renderSubscriptions();
      setFollowStatus("Platform subscriptions are unavailable; fetch sources manually.");
      return;
    }
    try {
      if (!loadOptions.silent) {
        setStatus("Loading subscriptions...");
      }
      const response = await CryptaPlatform.content.subscriptions.list(requestOptionsFrom(loadOptions));
      state.subscriptions = normalizeSubscriptionList(response);
      syncSourceSubscriptionMetadata();
      renderSources();
      renderSubscriptions();
      if (!loadOptions.silent) {
        setStatus("Subscriptions refreshed.");
      }
      setFollowStatus("Platform subscription metadata loaded.");
      await persistDurableState();
    } catch (error) {
      if (!loadOptions.silent) {
        setStatus(safeErrorMessage(error), "error");
      }
      renderSubscriptions();
      setFollowStatus("Subscription metadata could not be loaded.");
    }
  }

  async function createSubscriptionForSource(source) {
    if (!subscriptionHelpersAvailable()) {
      source.lastStatus = "Subscription helper unavailable";
      setFollowStatus("Platform subscriptions are unavailable; source remains manual.");
      return;
    }
    if (!isUskUri(source.uri)) {
      source.lastStatus = "Subscriptions require a USK URI";
      setFollowStatus("Only USK feed sources can be subscribed.");
      return;
    }
    try {
      const response = await CryptaPlatform.content.subscriptions.create({
        uri: source.uri,
        label: source.label,
        pollIntervalSeconds: subscriptionPollIntervalSeconds,
        maxBytes: rawFeedFetchMaxBytes,
        timeoutMillis: 30000,
      });
      const subscription = subscriptionFromResponse(response);
      updateSubscriptionState(subscription);
      source.subscriptionId = subscription.subscriptionId || "";
      source.lastStatus = "Subscribed";
      setFollowStatus("Platform subscription created.");
      await persistDurableState();
    } catch (error) {
      source.lastStatus = safeErrorMessage(error);
      setFollowStatus(source.lastStatus);
    }
  }

  async function refreshSubscription(subscriptionId) {
    if (!subscriptionHelpersAvailable()) {
      setFollowStatus("Platform subscriptions are unavailable.");
      return;
    }
    try {
      setStatus("Refreshing subscription...");
      const response = await CryptaPlatform.content.subscriptions.refresh(subscriptionId);
      const subscription = subscriptionFromResponse(response);
      updateSubscriptionState(subscription);
      const source = sourceForSubscription(subscription.subscriptionId);
      if (source) {
        await refreshSource(source, { follow: true, subscriptionSummary: subscription });
      }
      await persistDurableState();
      renderSources();
      renderSubscriptions();
      setStatus("Subscription refresh requested.", "success");
    } catch (error) {
      setStatus(safeErrorMessage(error), "error");
    }
  }

  async function pauseSubscription(subscriptionId) {
    await mutateSubscription(subscriptionId, "pause", "Subscription paused.");
  }

  async function resumeSubscription(subscriptionId) {
    await mutateSubscription(subscriptionId, "resume", "Subscription resumed.");
  }

  async function removeSubscription(subscriptionId) {
    if (!subscriptionHelpersAvailable()) {
      setFollowStatus("Platform subscriptions are unavailable.");
      return;
    }
    try {
      const response = await CryptaPlatform.content.subscriptions.remove(subscriptionId);
      const subscription = subscriptionFromResponse(response);
      state.subscriptions = state.subscriptions.filter(
        (item) => item.subscriptionId !== subscriptionId,
      );
      state.sources
        .filter((source) => source.subscriptionId === subscriptionId)
        .forEach((source) => {
          source.subscriptionId = "";
          source.followUsk = false;
          source.lastStatus = "Subscription removed";
        });
      renderSources();
      renderSubscriptions();
      setStatus(
        subscription && subscription.status === "deleted"
          ? "Subscription deleted."
          : "Subscription removed.",
        "success",
      );
      await persistDurableState();
    } catch (error) {
      setStatus(safeErrorMessage(error), "error");
    }
  }

  async function mutateSubscription(subscriptionId, action, message) {
    if (!subscriptionHelpersAvailable()) {
      setFollowStatus("Platform subscriptions are unavailable.");
      return;
    }
    try {
      const response = await CryptaPlatform.content.subscriptions[action](subscriptionId);
      updateSubscriptionState(subscriptionFromResponse(response));
      await persistDurableState();
      renderSources();
      renderSubscriptions();
      setStatus(message, "success");
    } catch (error) {
      setStatus(safeErrorMessage(error), "error");
    }
  }

  function subscriptionHelpersAvailable() {
    return (
      CryptaPlatform.content &&
      CryptaPlatform.content.subscriptions &&
      typeof CryptaPlatform.content.subscriptions.list === "function" &&
      typeof CryptaPlatform.content.subscriptions.create === "function"
    );
  }

  function requestOptionsFrom(source) {
    const options = {};
    ["signal", "headers", "bootstrap", "force", "refreshBootstrap"].forEach((name) => {
      if (source && Object.prototype.hasOwnProperty.call(source, name)) {
        options[name] = source[name];
      }
    });
    return options;
  }

  async function loadDurableState() {
    if (!dataHelpersAvailable()) {
      return;
    }
    try {
      const stored = await CryptaPlatform.data.records.getJson(dataNamespace, dataStateKey);
      if (!stored || (stored.schemaVersion !== dataSchemaVersion && stored.schemaVersion !== 1)) {
        return;
      }
      if (Array.isArray(stored.sources)) {
        state.sources = stored.sources.slice(0, maxSources).map(normalizeStoredSource).filter(Boolean);
      }
      state.selectedSourceId = stringValue(stored.selectedSourceId);
      if (Array.isArray(stored.fetchedSnapshots)) {
        state.fetchedSnapshots = stored.fetchedSnapshots
          .slice(0, maxRememberedSnapshots)
          .map(normalizeStoredSnapshot)
          .filter(Boolean);
      }
      if (stored.lastPublisherDraft && typeof stored.lastPublisherDraft === "object") {
        state.lastPublisherDraft = stored.lastPublisherDraft;
      }
    } catch (error) {
      // First launch or older nodes may not have a saved state record yet.
    }
  }

  async function persistDurableState() {
    if (!dataHelpersAvailable()) {
      return;
    }
    try {
      await CryptaPlatform.data.records.putJson({
        namespace: dataNamespace,
        key: dataStateKey,
        schemaVersion: dataSchemaVersion,
        value: durableStateValue(),
      });
    } catch (error) {
      setFollowStatus("Durable feed state could not be saved.");
    }
  }

  function durableStateValue() {
    return {
      schemaVersion: dataSchemaVersion,
      sources: state.sources.slice(0, maxSources).map(durableSource),
      selectedSourceId: state.selectedSourceId,
      fetchedSnapshots: state.fetchedSnapshots
        .slice(0, maxRememberedSnapshots)
        .map(durableSnapshot),
      lastPublisherDraft: publisherDraft(elements.publisherForm),
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

  async function publishSnapshot(event) {
    event.preventDefault();
    try {
      const entry = buildDraftEntry(elements.publisherForm);
      const snapshot = buildPublishedSnapshot(elements.publisherForm, entry);
      state.lastPublisherDraft = publisherDraft(elements.publisherForm);
      await persistDurableState();
      const result = await CryptaPlatform.feed.publishSnapshot({
        insertUri: fieldValue(elements.publisherForm, "insertUri"),
        identifier: fieldValue(elements.publisherForm, "identifier") || generatedId("feed-publish"),
        snapshot,
        contentType: feedSnapshotFormat.contentType,
        targetFilename: feedSnapshotFormat.defaultFilename,
      });
      rememberPublishResult(result);
      elements.publisherForm.reset();
      renderPublishResults();
      await refreshUploadQueue({ silent: true });
      setStatus("Feed snapshot publish queued.", "success");
    } catch (error) {
      setStatus(safeErrorMessage(error), "error");
    }
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
      renderQueue(snapshot);
      if (!refreshOptions.silent) {
        setStatus("Upload queue preview refreshed.");
      }
    } catch (error) {
      if (!refreshOptions.silent) {
        setStatus(safeErrorMessage(error), "error");
      }
      renderQueue(null);
    }
  }

  function renderSources() {
    if (state.sources.length === 0) {
      elements.sourceList.replaceChildren(text("p", "cr-empty", "Add a feed source to fetch entries."));
      return;
    }
    const list = document.createElement("div");
    list.className = "source-list";
    state.sources.forEach((source) => {
      const item = document.createElement("div");
      item.className = "source-item";
      const title = text("p", "entry-title", source.label);
      const uri = text("p", "source-uri", source.uri);
      const status = text(
        "p",
        "entry-meta",
        source.lastFetchedAt
          ? `${source.lastStatus} at ${source.lastFetchedAt}`
          : source.lastStatus,
      );
      const subscriptionStatus = subscriptionForSource(source);
      const actions = document.createElement("div");
      actions.className = "source-item__actions";
      actions.append(
        button("Select", "cr-button cr-button--secondary", () => selectSource(source.id)),
        button("Fetch", "cr-button cr-button--primary", () => refreshSource(source, { follow: false })),
      );
      if (!source.subscriptionId && source.followUsk && subscriptionHelpersAvailable() && isUskUri(source.uri)) {
        actions.append(
          button("Subscribe", "cr-button cr-button--secondary", () =>
            createSubscriptionForSource(source).then(() => {
              renderSources();
              renderSubscriptions();
            }),
          ),
        );
      }
      item.append(
        title,
        uri,
        status,
        text("p", "entry-meta", subscriptionStatusText(subscriptionStatus)),
        actions,
      );
      list.append(item);
    });
    elements.sourceList.replaceChildren(list);
  }

  function renderSubscriptions() {
    if (!elements.subscriptionList) {
      return;
    }
    if (!subscriptionHelpersAvailable()) {
      elements.subscriptionList.replaceChildren(
        text("p", "cr-empty", "Platform subscription helpers are unavailable."),
      );
      return;
    }
    if (state.subscriptions.length === 0) {
      elements.subscriptionList.replaceChildren(
        text("p", "cr-empty", "No platform subscriptions are registered."),
      );
      return;
    }
    const list = document.createElement("div");
    list.className = "source-list";
    state.subscriptions.forEach((subscription) => {
      const item = document.createElement("div");
      item.className = "source-item";
      const actions = document.createElement("div");
      actions.className = "source-item__actions";
      actions.append(
        button("Refresh", "cr-button cr-button--secondary", () =>
          refreshSubscription(subscription.subscriptionId),
        ),
      );
      if (subscription.paused || subscription.enabled === false || subscription.status === "paused") {
        actions.append(
          button("Resume", "cr-button cr-button--secondary", () =>
            resumeSubscription(subscription.subscriptionId),
          ),
        );
      } else {
        actions.append(
          button("Pause", "cr-button cr-button--secondary", () =>
            pauseSubscription(subscription.subscriptionId),
          ),
        );
      }
      actions.append(
        button("Delete", "cr-button cr-button--secondary", () =>
          removeSubscription(subscription.subscriptionId),
        ),
      );
      item.append(
        text("p", "entry-title", subscription.label || subscription.subscriptionId),
        text("p", "source-uri", subscription.sourceUri),
        summaryRow("Status", subscription.status),
        summaryRow("Last check", subscription.lastCheckAt),
        summaryRow("Last edition", subscription.lastSeenEdition),
        summaryRow("Updates", subscription.updateCount),
        summaryRow("Error", subscription.lastErrorCode || subscription.message),
        actions,
      );
      list.append(item);
    });
    elements.subscriptionList.replaceChildren(list);
  }

  function renderReader() {
    const snapshot = selectedSnapshot();
    if (!snapshot) {
      elements.readerContent.replaceChildren(
        text("p", "cr-empty", "Fetched feed content appears here as plain text."),
      );
      return;
    }
    const panel = document.createElement("div");
    panel.className = "reader-content";
    panel.append(
      summaryRow("Source", snapshot.sourceLabel),
      summaryRow("Fetched", snapshot.fetchedAt),
      summaryRow("Feed", snapshot.title),
      summaryRow("Updated", snapshot.updatedAt),
      summaryRow("URI", snapshot.sourceUri),
      summaryRow("Resolved", snapshot.resolvedUri),
      summaryRow("Bytes", snapshot.bytesLength),
    );
    if (snapshot.items.length === 0) {
      const entryCount = Number(snapshot.itemCount) || 0;
      panel.append(
        text(
          "p",
          "cr-empty",
          entryCount > 0
            ? `${entryCount} entries were seen in the last fetch. Fetch this source again to view entries.`
            : "No entries were returned for this snapshot.",
        ),
      );
    }
    snapshot.items.forEach((entry) => {
      const item = document.createElement("article");
      item.className = "entry-item";
      item.append(
        text("h3", "entry-title", entry.title),
        text("p", "entry-meta", entry.publishedAt),
        text("p", "entry-body", entry.summary),
        text("p", "source-uri", entry.uri),
        text("p", "entry-meta", entry.tags.join(", ")),
      );
      panel.append(item);
    });
    elements.readerContent.replaceChildren(panel);
  }

  function renderPublishResults() {
    if (state.publishResults.length === 0) {
      elements.publishResult.replaceChildren(
        text("p", "cr-empty", "Publish results stay only in this page's memory."),
      );
      return;
    }
    const list = document.createElement("div");
    list.className = "publish-summary";
    state.publishResults.forEach((result) => {
      const item = document.createElement("div");
      item.className = "publish-item";
      item.append(
        summaryRow("When", result.at),
        summaryRow("Identifier", result.identifier),
        summaryRow("Outcome", result.outcome),
      );
      list.append(item);
    });
    elements.publishResult.replaceChildren(list);
  }

  function renderQueue(snapshot) {
    if (!snapshot || typeof snapshot !== "object") {
      elements.queuePreview.replaceChildren(text("p", "cr-empty", "No upload queue content was returned."));
      return;
    }
    const panel = document.createElement("div");
    panel.className = "queue-content";
    panel.append(
      summaryRow("Queue page", stringValue(snapshot.page) || "uploads"),
      summaryRow("Title", stringValue(snapshot.pageTitle) || "Upload queue"),
    );
    const rows = queueRowsFromSnapshot(snapshot).slice(0, 10);
    if (rows.length === 0) {
      panel.append(text("p", "cr-empty", "No visible upload queue entries were returned."));
    }
    rows.forEach((item) => {
      const row = document.createElement("div");
      row.className = "queue-item";
      row.append(text("p", "entry-title", item.label), text("p", "entry-body", item.detail));
      panel.append(row);
    });
    elements.queuePreview.replaceChildren(panel);
  }

  function queueRowsFromSnapshot(snapshot) {
    if (Array.isArray(snapshot.items)) {
      return snapshot.items.map(queueRowFromItem).filter(Boolean);
    }
    const rows = queueRowsFromHtml(snapshot.contentHtml);
    if (rows.length > 0) {
      return rows;
    }
    const summary = compactQueueText(snapshot.summary);
    return summary ? [{ label: "Summary", detail: summary }] : [];
  }

  function queueRowFromItem(item) {
    if (!item || typeof item !== "object") {
      return null;
    }
    const label = stringValue(item.identifier || item.name || item.id) || "Queue item";
    const detail = [
      item.status || item.outcome,
      item.uri || item.insertUri || item.targetUri,
      item.progress || item.priority,
    ]
      .map(compactQueueText)
      .filter(Boolean)
      .join(" | ");
    return { label, detail: detail || "Queued" };
  }

  function queueRowsFromHtml(contentHtml) {
    const html = typeof contentHtml === "string" ? contentHtml : "";
    if (!html.trim()) {
      return [];
    }
    const documentValue = new DOMParser().parseFromString(html, "text/html");
    removeUnsafeParsedNodes(documentValue);
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

  function normalizeSubscriptionList(response) {
    const subscriptions = response && response.subscriptions;
    return Array.isArray(subscriptions) ? subscriptions.map(normalizeSubscription).filter(Boolean) : [];
  }

  function subscriptionFromResponse(response) {
    return normalizeSubscription(response && response.subscription ? response.subscription : response);
  }

  function normalizeSubscription(subscription) {
    if (!subscription || typeof subscription !== "object") {
      return null;
    }
    const subscriptionId = stringValue(subscription.subscriptionId);
    if (!subscriptionId) {
      return null;
    }
    return {
      subscriptionId,
      appId: boundedText(subscription.appId, maxDisplayLabelLength),
      label: boundedText(subscription.label, maxDisplayLabelLength),
      sourceUri: normalizedCryptaContentUri(subscription.sourceUri, ["USK"]),
      enabled: subscription.enabled !== false,
      paused: !!subscription.paused,
      status: boundedText(subscription.status, maxDisplayLabelLength) || "scheduled",
      lastCheckAt: boundedText(subscription.lastCheckAt, maxDisplayLabelLength),
      nextCheckAt: boundedText(subscription.nextCheckAt, maxDisplayLabelLength),
      lastSuccessAt: boundedText(subscription.lastSuccessAt, maxDisplayLabelLength),
      lastFailureAt: boundedText(subscription.lastFailureAt, maxDisplayLabelLength),
      failureCount: boundedCount(subscription.failureCount, maxEntriesPerSnapshot),
      lastErrorCode: boundedText(subscription.lastErrorCode, maxDisplayLabelLength),
      lastSeenResolvedUri: normalizedCryptaContentUri(subscription.lastSeenResolvedUri, ["USK"]),
      lastSeenEdition: boundedCount(subscription.lastSeenEdition, 1_000_000_000),
      contentSha256: boundedText(subscription.contentSha256, 64),
      bytesLength: boundedCount(subscription.bytesLength, 1_048_576),
      updateCount: boundedCount(subscription.updateCount, 1_000_000),
      message: boundedText(subscription.message, maxDisplayLabelLength),
    };
  }

  function updateSubscriptionState(subscription) {
    if (!subscription) {
      return;
    }
    const index = state.subscriptions.findIndex(
      (item) => item.subscriptionId === subscription.subscriptionId,
    );
    if (index >= 0) {
      state.subscriptions.splice(index, 1, subscription);
    } else {
      state.subscriptions.unshift(subscription);
    }
    syncSourceSubscriptionMetadata();
  }

  function syncSourceSubscriptionMetadata() {
    const subscriptionsById = new Map();
    const subscriptionsBySourceUri = new Map();
    state.subscriptions.forEach((subscription) => {
      subscriptionsById.set(subscription.subscriptionId, subscription);
      if (subscription.sourceUri && !subscriptionsBySourceUri.has(subscription.sourceUri)) {
        subscriptionsBySourceUri.set(subscription.sourceUri, subscription);
      }
    });
    state.sources.forEach((source) => {
      const subscription =
        subscriptionsById.get(source.subscriptionId) || subscriptionsBySourceUri.get(source.uri);
      if (!subscription) {
        if (source.subscriptionId) {
          source.subscriptionId = "";
          source.lastStatus = "Subscription not found";
        }
        return;
      }
      source.subscriptionId = subscription.subscriptionId;
      source.followUsk = true;
      source.lastStatus = subscription.status || source.lastStatus;
    });
  }

  function subscriptionForSource(source) {
    if (!source) {
      return null;
    }
    return (
      state.subscriptions.find((subscription) => subscription.subscriptionId === source.subscriptionId) ||
      state.subscriptions.find((subscription) => subscription.sourceUri === source.uri) ||
      null
    );
  }

  function sourceForSubscription(subscriptionId) {
    return (
      state.sources.find((source) => source.subscriptionId === subscriptionId) ||
      state.sources.find((source) => {
        const subscription = state.subscriptions.find(
          (item) => item.subscriptionId === subscriptionId,
        );
        return subscription && source.uri === subscription.sourceUri;
      }) ||
      null
    );
  }

  function subscriptionStatusText(subscription) {
    if (!subscription) {
      return "No platform subscription";
    }
    const parts = [`Subscription ${subscription.status}`];
    if (subscription.lastSeenEdition) {
      parts.push(`edition ${subscription.lastSeenEdition}`);
    }
    if (subscription.updateCount) {
      parts.push(`${subscription.updateCount} update(s)`);
    }
    return parts.join(" | ");
  }

  function queueRowFromTableRow(row) {
    const cells = Array.from(row.querySelectorAll("td")).map((cell) => compactQueueText(cell.textContent));
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

  function normalizeSnapshot(source, snapshot) {
    const response = snapshot && snapshot.response ? snapshot.response : {};
    const feedSnapshot = snapshot && snapshot.snapshot ? snapshot.snapshot : snapshot;
    const feedSource =
      feedSnapshot && feedSnapshot.source && typeof feedSnapshot.source === "object"
        ? feedSnapshot.source
        : {};
    const items = itemsFromSnapshot(feedSnapshot).slice(0, maxEntriesPerSnapshot);
    return {
      sourceId: source.id,
      sourceLabel: boundedText(source.label, maxDisplayLabelLength),
      sourceUri: normalizedCryptaContentUri(source.uri, ["CHK", "SSK", "USK", "KSK"]),
      resolvedUri: normalizedCryptaContentUri(feedSource.resolvedUri || response.resolvedUri, [
        "CHK",
        "SSK",
        "USK",
        "KSK",
      ]),
      bytesLength: boundedCount(response.bytesLength, 1_048_576),
      title: boundedText(feedSnapshot && feedSnapshot.title, maxFeedTitleLength) || source.label,
      updatedAt: boundedText(feedSnapshot && feedSnapshot.updatedAt, maxDisplayLabelLength),
      fetchedAt: new Date().toLocaleTimeString(),
      itemCount: items.length,
      items,
    };
  }

  function itemsFromSnapshot(snapshot) {
    if (snapshot && Array.isArray(snapshot.items)) {
      return snapshot.items.map(normalizeEntry);
    }
    if (snapshot && Array.isArray(snapshot.entries)) {
      return snapshot.entries.map(normalizeEntry);
    }
    if (snapshot && typeof snapshot.contentText === "string") {
      return itemsFromText(snapshot.contentText);
    }
    if (snapshot && typeof snapshot.text === "string") {
      return itemsFromText(snapshot.text);
    }
    if (snapshot && typeof snapshot.content === "string") {
      return itemsFromText(snapshot.content);
    }
    if (typeof snapshot === "string") {
      return itemsFromText(snapshot);
    }
    return [];
  }

  function itemsFromText(textValue) {
    const sourceText = stringValue(textValue);
    if (!sourceText) {
      return [];
    }
    const parsed = parseXmlFeed(sourceText);
    if (parsed.length > 0) {
      return parsed;
    }
    return [
      {
        title: "Fetched text",
        publishedAt: new Date().toISOString(),
        summary: boundedText(sourceText, maxFeedBodyLength),
        uri: "",
        tags: [],
      },
    ];
  }

  function parseXmlFeed(textValue) {
    const parser = new DOMParser();
    const documentValue = parser.parseFromString(textValue, "application/xml");
    if (documentValue.querySelector("parsererror")) {
      return [];
    }
    removeUnsafeParsedNodes(documentValue, { keepFeedLinks: true });
    const items = Array.from(documentValue.querySelectorAll("item, entry"));
    return items.slice(0, maxEntriesPerSnapshot).map((item) => ({
      title: boundedText(childText(item, "title"), maxFeedTitleLength) || "Untitled entry",
      publishedAt:
        boundedText(
          childText(item, "updated") || childText(item, "published") || childText(item, "pubDate"),
          maxDisplayLabelLength,
        ),
      summary: boundedText(
        childText(item, "summary") || childText(item, "description") || childText(item, "content"),
        maxFeedBodyLength,
      ),
      uri: entryLink(item),
      tags: [],
    }));
  }

  function snapshotFromTextResponse(source, response) {
    const textValue =
      typeof response === "string"
        ? response
        : stringValue(
            response && (response.contentText || response.text || response.content || response.body),
          );
    const parsedSnapshot = parseCanonicalSnapshot(textValue);
    if (parsedSnapshot) {
      return { response, snapshot: parsedSnapshot };
    }
    return {
      response,
      snapshot: {
        type: feedSnapshotFormat.type,
        title: source.label,
        updatedAt: new Date().toISOString(),
        source: {
          uri: source.uri,
          resolvedUri: stringValue(response && response.resolvedUri),
        },
        author: {},
        items: itemsFromText(textValue),
      },
    };
  }

  function parseCanonicalSnapshot(textValue) {
    const sourceText = typeof textValue === "string" ? textValue : "";
    if (
      !/^\s*[\[{]/.test(sourceText) ||
      !CryptaPlatform.feed ||
      typeof CryptaPlatform.feed.parseSnapshot !== "function"
    ) {
      return null;
    }
    const profileType = feedSnapshotProfileType(sourceText);
    try {
      return CryptaPlatform.feed.parseSnapshot(sourceText);
    } catch (error) {
      if (
        error.code === "content_format_ambiguous_json" ||
        profileType === feedSnapshotFormat.type ||
        profileType.startsWith("crypta.feed.snapshot.")
      ) {
        throw error;
      }
      return null;
    }
  }

  function feedSnapshotProfileType(textValue) {
    try {
      const parsed = JSON.parse(textValue);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? stringValue(parsed.type)
        : "";
    } catch (error) {
      return "";
    }
  }

  function durableSource(source) {
    return {
      id: boundedText(source.id, maxDisplayLabelLength),
      label: boundedText(source.label, maxDisplayLabelLength),
      uri: normalizedCryptaContentUri(source.uri, ["CHK", "SSK", "USK", "KSK"]),
      followUsk: !!source.followUsk,
      subscriptionId: boundedText(source.subscriptionId, maxDisplayLabelLength),
      lastFetchedAt: boundedText(source.lastFetchedAt, maxDisplayLabelLength),
      lastStatus: boundedText(source.lastStatus, maxDisplayLabelLength),
    };
  }

  function durableSnapshot(snapshot) {
    return {
      sourceId: boundedText(snapshot.sourceId, maxDisplayLabelLength),
      sourceLabel: boundedText(snapshot.sourceLabel, maxDisplayLabelLength),
      sourceUri: normalizedCryptaContentUri(snapshot.sourceUri, ["CHK", "SSK", "USK", "KSK"]),
      resolvedUri: normalizedCryptaContentUri(snapshot.resolvedUri, ["CHK", "SSK", "USK", "KSK"]),
      bytesLength: boundedCount(snapshot.bytesLength, 1_048_576),
      title: boundedText(snapshot.title, maxFeedTitleLength),
      updatedAt: boundedText(snapshot.updatedAt, maxDisplayLabelLength),
      fetchedAt: boundedText(snapshot.fetchedAt, maxDisplayLabelLength),
      itemCount: snapshotItemCount(snapshot),
    };
  }

  function normalizeStoredSource(source) {
    if (!source || typeof source !== "object") {
      return null;
    }
    const id = stringValue(source.id);
    const uri = normalizedCryptaContentUri(source.uri, ["CHK", "SSK", "USK", "KSK"]);
    if (!id || !uri) {
      return null;
    }
    return {
      id: boundedText(id, maxDisplayLabelLength),
      label: boundedText(source.label, maxDisplayLabelLength) || "Untitled feed",
      uri,
      followUsk: !!source.followUsk,
      subscriptionId: boundedText(source.subscriptionId, maxDisplayLabelLength),
      lastFetchedAt: boundedText(source.lastFetchedAt, maxDisplayLabelLength),
      lastStatus: boundedText(source.lastStatus, maxDisplayLabelLength) || "Not fetched",
    };
  }

  function normalizeStoredSnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== "object") {
      return null;
    }
    const sourceId = stringValue(snapshot.sourceId);
    if (!sourceId) {
      return null;
    }
    return {
      sourceId: boundedText(sourceId, maxDisplayLabelLength),
      sourceLabel: boundedText(snapshot.sourceLabel, maxDisplayLabelLength),
      sourceUri: normalizedCryptaContentUri(snapshot.sourceUri, ["CHK", "SSK", "USK", "KSK"]),
      resolvedUri: normalizedCryptaContentUri(snapshot.resolvedUri, ["CHK", "SSK", "USK", "KSK"]),
      bytesLength: boundedCount(snapshot.bytesLength, 1_048_576),
      title: boundedText(snapshot.title, maxFeedTitleLength),
      updatedAt: boundedText(snapshot.updatedAt, maxDisplayLabelLength),
      fetchedAt: boundedText(snapshot.fetchedAt, maxDisplayLabelLength),
      itemCount: snapshotItemCount(snapshot),
      items: [],
    };
  }

  function snapshotItemCount(snapshot) {
    if (!snapshot || typeof snapshot !== "object") {
      return 0;
    }
    const explicitCount = Number(snapshot.itemCount);
    if (Number.isFinite(explicitCount) && explicitCount > 0) {
      return Math.min(Math.floor(explicitCount), maxEntriesPerSnapshot);
    }
    return Array.isArray(snapshot.items)
      ? Math.min(snapshot.items.length, maxEntriesPerSnapshot)
      : 0;
  }

  function publisherDraft(form) {
    return {
      authorName: boundedText(fieldValue(form, "authorName"), maxDisplayLabelLength),
      authorProfileUri: normalizedCryptaContentUri(fieldValue(form, "authorProfileUri"), [
        "CHK",
        "SSK",
        "USK",
        "KSK",
      ]),
      entryBody: boundedText(fieldValue(form, "entryBody"), maxFeedBodyLength),
      entryTags: boundedText(fieldValue(form, "entryTags"), maxFeedTitleLength),
      entryTitle: boundedText(fieldValue(form, "entryTitle"), maxFeedTitleLength),
      entryUri: normalizedCryptaContentUri(fieldValue(form, "entryUri"), [
        "CHK",
        "SSK",
        "USK",
        "KSK",
      ]),
      feedTitle: boundedText(fieldValue(form, "feedTitle"), maxFeedTitleLength),
      identifier: boundedText(fieldValue(form, "identifier"), maxDisplayLabelLength),
    };
  }

  function restorePublisherDraft() {
    const draft = state.lastPublisherDraft || {};
    Object.keys(draft)
      .filter((name) => name !== "insertUri")
      .forEach((name) => setFieldValue(elements.publisherForm, name, draft[name]));
  }

  function setFieldValue(form, name, value) {
    const field = form.elements.namedItem(name);
    if (field && "value" in field) {
      field.value = stringValue(value);
    }
  }

  function buildDraftEntry(form) {
    return {
      id: generatedId("entry"),
      title: boundedText(fieldValue(form, "entryTitle"), maxFeedTitleLength),
      summary: boundedText(fieldValue(form, "entryBody"), maxFeedBodyLength),
      uri: normalizedCryptaContentUri(fieldValue(form, "entryUri"), ["CHK", "SSK", "USK", "KSK"]),
      publishedAt: new Date().toISOString(),
      tags: tagsFromField(fieldValue(form, "entryTags")),
    };
  }

  function buildPublishedSnapshot(form, entry) {
    const source = selectedSource();
    const snapshot = selectedSnapshot();
    return {
      type: feedSnapshotFormat.type,
      title:
        boundedText(fieldValue(form, "feedTitle"), maxFeedTitleLength) ||
        (source ? source.label : "Feed snapshot"),
      updatedAt: new Date().toISOString(),
      source: {
        uri: source ? source.uri : "",
        resolvedUri: snapshot ? snapshot.resolvedUri : "",
      },
      author: {
        name: boundedText(fieldValue(form, "authorName"), maxDisplayLabelLength),
        profileUri: normalizedCryptaContentUri(fieldValue(form, "authorProfileUri"), [
          "CHK",
          "SSK",
          "USK",
          "KSK",
        ]),
      },
      items: [entry].concat(snapshot ? snapshot.items : []).slice(0, maxEntriesPerSnapshot),
    };
  }

  function rememberSnapshot(snapshot) {
    state.fetchedSnapshots.unshift(snapshot);
    state.fetchedSnapshots = state.fetchedSnapshots.slice(0, maxRememberedSnapshots);
    state.selectedSourceId = snapshot.sourceId;
  }

  function rememberPublishResult(result) {
    state.publishResults.unshift({
      at: new Date().toLocaleTimeString(),
      identifier: stringValue(result && (result.identifier || result.requestIdentifier || result.requestId)),
      outcome: stringValue(result && (result.outcome || result.status)) || "Queued",
    });
    state.publishResults = state.publishResults.slice(0, maxPublishResults);
  }

  function selectSource(sourceId) {
    state.selectedSourceId = sourceId;
    persistDurableState();
    renderSources();
    renderReader();
  }

  function selectedSource() {
    return state.sources.find((source) => source.id === state.selectedSourceId) || state.sources[0] || null;
  }

  function selectedSnapshot() {
    if (state.selectedSourceId) {
      return (
        state.fetchedSnapshots.find((snapshot) => snapshot.sourceId === state.selectedSourceId) ||
        null
      );
    }
    const source = state.sources[0] || null;
    if (source) {
      return state.fetchedSnapshots.find((snapshot) => snapshot.sourceId === source.id) || null;
    }
    return state.fetchedSnapshots[0] || null;
  }

  function normalizeEntry(entry) {
    return {
      title: boundedText(entry && entry.title, maxFeedTitleLength) || "Untitled entry",
      publishedAt: boundedText(
        entry && (entry.publishedAt || entry.date || entry.updated || entry.published),
        maxDisplayLabelLength,
      ),
      summary: boundedText(
        entry && (entry.summary || entry.body || entry.content || entry.text),
        maxFeedBodyLength,
      ),
      uri: normalizedCryptaContentUri(entry && entry.uri, ["CHK", "SSK", "USK", "KSK"]),
      tags: Array.isArray(entry && entry.tags)
        ? entry.tags.map((tag) => boundedText(tag, maxTagLength)).filter(Boolean).slice(0, 12)
        : [],
    };
  }

  function childText(element, selector) {
    const child = element.querySelector(selector);
    return child ? stringValue(child.textContent) : "";
  }

  function entryLink(element) {
    const link = element.querySelector("link[rel=\"alternate\"]") || element.querySelector("link");
    if (!link) {
      return "";
    }
    return normalizedCryptaContentUri(link.getAttribute("href") || link.textContent, [
      "CHK",
      "SSK",
      "USK",
      "KSK",
    ]);
  }

  function fieldValue(form, name) {
    const field = form.elements.namedItem(name);
    return field && "value" in field ? stringValue(field.value) : "";
  }

  function checkboxValue(form, name) {
    const field = form.elements.namedItem(name);
    return field instanceof HTMLInputElement && field.checked;
  }

  function isUskUri(value) {
    return !!normalizedCryptaContentUri(value, ["USK"]);
  }

  function tagsFromField(value) {
    return stringValue(value)
      .split(",")
      .map((tag) => boundedText(tag, maxTagLength))
      .filter(Boolean)
      .slice(0, 12);
  }

  function stringValue(value) {
    return typeof value === "string" ? value.trim() : value == null ? "" : String(value).trim();
  }

  function boundedText(value, maxLength) {
    const textValue = stringValue(value).replace(unsafeControlPattern(), " ");
    if (textValue.length <= maxLength) {
      return textValue;
    }
    return `${textValue.slice(0, Math.max(0, maxLength - 3))}...`;
  }

  function numberValue(value) {
    if (Number.isFinite(value)) {
      return value;
    }
    if (typeof value === "string" && /^[0-9]+$/.test(value.trim())) {
      return Number.parseInt(value.trim(), 10);
    }
    return 0;
  }

  function boundedCount(value, maxValue) {
    const count = Math.floor(numberValue(value));
    if (!Number.isFinite(count) || count < 0) {
      return 0;
    }
    return Math.min(count, maxValue);
  }

  function normalizedCryptaContentUri(value, allowedKinds) {
    const uri = stringValue(value);
    if (
      !uri ||
      uri.length > maxContentUriLength ||
      /[\s\\\u0000]/.test(uri) ||
      uri.includes("?") ||
      uri.includes("#")
    ) {
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
    return allowedKinds.some(
      (kind) => upper.startsWith(`${kind}@`) && runtimeUri.length > kind.length + 1,
    )
      ? uri
      : "";
  }

  function removeUnsafeParsedNodes(documentValue, options) {
    documentValue
      .querySelectorAll(unsafeParsedElementSelector(options))
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

  function unsafeParsedElementSelector(options) {
    if (options && options.keepFeedLinks) {
      return "script, style, template, noscript, iframe, frame, frameset, object, embed, meta, base, svg, math";
    }
    return "script, style, template, noscript, iframe, frame, frameset, object, embed, link, meta, base, svg, math";
  }

  function unsafeControlPattern() {
    return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
  }

  function compactQueueText(value) {
    return boundedText(stringValue(value).replace(/\s+/g, " "), 260);
  }

  function generatedId(prefix) {
    const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, "");
    const random = Math.random().toString(36).slice(2, 8);
    return `${prefix}-${timestamp}-${random}`;
  }

  function summaryRow(label, value) {
    const row = document.createElement("p");
    row.className = "summary-row";
    const strong = document.createElement("strong");
    strong.textContent = `${label}: `;
    row.append(strong, document.createTextNode(stringValue(value) || "Unavailable"));
    return row;
  }

  function text(tagName, className, value) {
    const element = document.createElement(tagName);
    element.className = className;
    element.textContent = stringValue(value);
    return element;
  }

  function button(label, className, action) {
    const element = document.createElement("button");
    element.className = className;
    element.type = "button";
    element.textContent = label;
    element.addEventListener("click", action);
    return element;
  }

  function setStatus(message, kind) {
    elements.status.textContent = stringValue(message);
    elements.status.className = `cr-status ${statusClass(kind)}`;
  }

  function setFollowStatus(message) {
    elements.followStatus.textContent = stringValue(message);
  }

  function safeErrorMessage(error) {
    const fallback = "Feed request failed. Retry refresh, resubscribe, or use Operator RC Recovery.";
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
    return boundedText(message, 240);
  }

  function sensitiveDiagnosticPattern() {
    return /(crypta:(?:ssk|usk)@|(?:ssk|usk)@|authorization|bearer|token|private key|identity material|browser session|form password|raw\s+(?:(?:fetched|feed|request|response|trust\s+statement|social\s+message|profile|app[-\s]data)\s+)?(?:content|document|body|message|payload|value|app[-\s]data)|[A-Za-z]:\\|\/(?:home|Users|work|tmp|var)\/)/i;
  }

  function statusClass(kind) {
    if (kind === "success") {
      return "cr-status--success";
    }
    if (kind === "error") {
      return "cr-status--danger";
    }
    return "cr-status--info";
  }
})();
