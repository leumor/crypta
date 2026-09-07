(function (window) {
  "use strict";

  if (window.CryptaPlatform) {
    return;
  }

  const defaultPlatformApiRoot = "/api/v1/";
  const bootstrapResourcePath = ".well-known/cryptad-bootstrap.json";
  const bootstrapNonceHeader = "X-Crypta-App-Bootstrap-Nonce";
  const bootstrapNonceFragmentParameter = "cryptadBootstrapNonce";
  const removedElementSelector =
    "script, style, template, iframe, frame, frameset, object, embed, link, meta, base";
  const urlAttributeNames = new Set(["href", "src", "action", "formaction"]);
  const appIdPattern = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;
  const contentFormats = Object.freeze({
    mailEnvelope: Object.freeze({
      id: "crypta.mail.envelope.v1", majorVersion: 1, status: "experimental",
      contentType: "application/vnd.crypta.mail+json", defaultFilename: "mail-envelope.json",
      maxDocumentBytes: 65536, signed: false, encrypted: true,
      canonicalization: "strict_flat_json_hpke_authenticated_header",
      unknownFieldPolicy: "reject_unknown_fields",
      futureVersionPolicy: "reject_unknown_major_accept_known_minor_only",
      deprecationPolicy: "explicit_warning_or_reject",
    }),
    profileDocument: Object.freeze({
      id: "crypta.profile.v1",
      schema: "crypta.profile.v1",
      majorVersion: 1,
      status: "experimental",
      contentType: "application/vnd.crypta.profile+json",
      defaultFilename: "profile.json",
      maxDocumentBytes: 65536,
      maxSignedPayloadBytes: 32768,
      signed: true,
      signingDomain: "profile.publish.v1",
      signingPurpose: "profile.publish.v1",
      canonicalization: "profile_payload_json",
      unknownFieldPolicy: "reject_unknown_fields",
      futureVersionPolicy: "reject_unknown_major_accept_known_minor_only",
      deprecationPolicy: "explicit_warning_or_reject",
    }),
    feedSnapshot: Object.freeze({
      id: "crypta.feed.snapshot.v1",
      type: "crypta.feed.snapshot.v1",
      majorVersion: 1,
      status: "stable",
      contentType: "application/vnd.crypta.feed+json",
      defaultFilename: "feed.json",
      maxDocumentBytes: 65536,
      signed: false,
      canonicalization: "deterministic_snapshot_json",
      unknownFieldPolicy: "reject_unknown_fields",
      futureVersionPolicy: "reject_unknown_major_accept_known_minor_only",
      deprecationPolicy: "explicit_warning_or_reject",
    }),
    trustStatement: Object.freeze({
      id: "crypta.trust.statement.v1",
      type: "crypta.trust.statement.v1",
      majorVersion: 1,
      status: "experimental",
      contentType: "application/vnd.crypta.trust+json",
      defaultFilename: "trust.json",
      maxDocumentBytes: 65536,
      maxSignedPayloadBytes: 32768,
      signed: true,
      signingDomain: "crypta.trust.statement.v1",
      canonicalization: "domain_separator_newline_canonical_payload_json",
      unknownFieldPolicy: "reject_unknown_fields",
      futureVersionPolicy: "reject_unknown_major_accept_known_minor_only",
      deprecationPolicy: "explicit_warning_or_reject",
    }),
    socialMessage: Object.freeze({
      id: "crypta.social.message.v1",
      type: "crypta.social.message.v1",
      majorVersion: 1,
      status: "experimental",
      contentType: "application/json",
      maxDocumentBytes: 65536,
      maxSignedPayloadBytes: 32768,
      signed: true,
      signingDomain: "crypta.social.message.v1",
      canonicalization: "domain_separator_newline_canonical_message_json",
      unknownFieldPolicy: "reject_unknown_fields",
      futureVersionPolicy: "reject_unknown_major_accept_known_minor_only",
      deprecationPolicy: "explicit_warning_or_reject",
    }),
    socialOutbox: Object.freeze({
      id: "crypta.social.outbox.v1",
      type: "crypta.social.outbox.v1",
      majorVersion: 1,
      status: "experimental",
      contentType: "application/vnd.crypta.social.outbox+json",
      defaultFilename: "social-outbox.json",
      maxDocumentBytes: 65536,
      signed: false,
      canonicalization: "deterministic_outbox_json_with_signed_message_entries",
      unknownFieldPolicy: "reject_unknown_fields",
      futureVersionPolicy: "reject_unknown_major_accept_known_minor_only",
      deprecationPolicy: "explicit_warning_or_reject",
    }),
  });
  const feedSnapshotType = contentFormats.feedSnapshot.type;
  const feedSnapshotContentType = contentFormats.feedSnapshot.contentType;
  const feedSnapshotTargetFilename = contentFormats.feedSnapshot.defaultFilename;
  const feedSnapshotMaxDocumentBytes = contentFormats.feedSnapshot.maxDocumentBytes;
  const feedSnapshotMaxEntries = 100;
  const trustStatementType = contentFormats.trustStatement.type;
  const trustStatementContentType = contentFormats.trustStatement.contentType;
  const trustStatementTargetFilename = contentFormats.trustStatement.defaultFilename;

  let currentBootstrap = null;
  let currentAppId = null;
  let currentBrowserSessionToken = "";
  let currentBootstrapNonce = "";
  let loadingAppId = null;
  let loadingBootstrap = null;

  async function loadBootstrap(options) {
    const rawAppId = explicitAppId(options) || inferAppId();
    const requestedAppId = rawAppId ? normalizeAppId(rawAppId) : null;

    const force = !!(options && options.force);
    if (!force && currentBootstrap && bootstrapMatchesRequest(currentBootstrap, requestedAppId)) {
      return copyBootstrap(currentBootstrap);
    }
    if (
      !force &&
      loadingBootstrap &&
      (requestedAppId === null || loadingAppId === requestedAppId)
    ) {
      return loadingBootstrap.then(copyBootstrap);
    }

    loadingAppId = requestedAppId;
    const inFlightBootstrap = fetchBootstrap(requestedAppId)
      .then((bootstrap) => {
        currentBootstrap = bootstrap;
        currentAppId = bootstrap.appId;
        return bootstrap;
      })
      .finally(() => {
        if (loadingBootstrap === inFlightBootstrap) {
          loadingAppId = null;
          loadingBootstrap = null;
        }
      });
    loadingBootstrap = inFlightBootstrap;
    return inFlightBootstrap.then(copyBootstrap);
  }

  function current() {
    return currentBootstrap ? copyBootstrap(currentBootstrap) : null;
  }

  function currentId() {
    if (currentBootstrap && currentBootstrap.appId) {
      return currentBootstrap.appId;
    }
    const inferredAppId = inferAppId();
    return inferredAppId ? normalizeAppId(inferredAppId) : null;
  }

  async function fetchBootstrap(appId) {
    const urls = bootstrapUrls(appId);
    const headers = bootstrapHeaders();
    let lastResponse = null;
    let lastData = {};
    for (let index = 0; index < urls.length; index += 1) {
      const response = await fetch(urls[index], {
        headers,
        credentials: "omit",
      });
      const data = await readJson(response);
      if (response.ok) {
        return finishBootstrap(appId, data);
      }
      lastResponse = response;
      lastData = data;
      if (index + 1 >= urls.length) {
        break;
      }
    }
    throw new Error(responseErrorMessage(lastData, lastResponse));
  }

  function finishBootstrap(appId, data) {
    const bootstrap = sanitizeBootstrap(data);
    const browserSessionToken = sessionTokenFromBootstrap(data);
    if (bootstrap.appId) {
      bootstrap.appId = normalizeAppId(bootstrap.appId);
    }
    if (bootstrap.appId && appId && bootstrap.appId !== appId) {
      throw new Error("Bootstrap app id does not match the requested app.");
    }
    if (!bootstrap.appId && appId) {
      bootstrap.appId = appId;
    }
    if (!bootstrap.appId) {
      throw new Error("Bootstrap response did not include a Cryptad app id.");
    }
    currentBrowserSessionToken = browserSessionToken;
    return bootstrap;
  }

  function bootstrapHeaders() {
    const headers = { Accept: "application/json" };
    const nonce = bootstrapNonce();
    if (nonce) {
      headers[bootstrapNonceHeader] = nonce;
    }
    return headers;
  }

  function bootstrapNonce() {
    const nonce = bootstrapNonceFromHash(window.location.hash);
    if (nonce) {
      currentBootstrapNonce = nonce;
      return nonce;
    }
    return currentBootstrapNonce;
  }

  function bootstrapNonceFromHash(hash) {
    const value = typeof hash === "string" ? hash.trim() : "";
    if (!value || value === "#") {
      return "";
    }
    const params = new URLSearchParams(value.startsWith("#") ? value.substring(1) : value);
    const nonce = params.get(bootstrapNonceFragmentParameter);
    return typeof nonce === "string" ? nonce.trim() : "";
  }

  async function mailCommand(command, payload) {
    const allowed = ["initialize", "export-contact", "import-contact", "approve-contact", "revoke-contact", "save-draft", "preview-send", "confirm-send", "import-reference", "retry", "read", "status", "backup", "restore"];
    if (!allowed.includes(command)) throw new Error("Unsupported Mail command.");
    const bytes = new TextEncoder().encode(JSON.stringify(payload || {}));
    if (bytes.length > 280000) throw new Error("Mail request is too large.");
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    const submitted = await apiPostForm("mail/command", { command, payloadBase64: btoa(binary) });
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      const response = await apiPostForm("mail/result", { requestId: submitted.mail.requestId });
      if (response.mail.status === "complete") {
        if (response.mail.payloadBase64.length > 393216) throw new Error("Mail response is too large.");
        const raw = atob(response.mail.payloadBase64);
        return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(raw, c => c.charCodeAt(0))));
      }
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    throw new Error("Mail worker timed out. Check operation status before retrying.");
  }

  async function apiGet(path, options) {
    const requestOptions = options || {};
    if (requestOptions.bootstrap !== false) {
      await ensureBootstrap(requestOptions);
    }

    try {
      return await fetchApiGet(path, requestOptions);
    } catch (error) {
      if (!shouldRefreshAfterSessionError(error, requestOptions)) {
        throw error;
      }
      await refreshBootstrap(requestOptions);
      return fetchApiGet(path, requestOptions);
    }
  }

  async function fetchApiGet(path, requestOptions) {
    const url = apiUrl(path);
    applySearchParams(url, requestOptions.params || requestOptions.searchParams || requestOptions.query);

    const headers = appSessionHeaders(requestOptions.headers);
    const response = await fetch(url, {
      method: "GET",
      headers,
      signal: requestOptions.signal,
      credentials: "omit",
    });
    return readJsonOrThrow(response);
  }

  async function apiPostForm(path, formDataOrParams, options) {
    return submitFormMutation("POST", path, formDataOrParams, options);
  }

  async function apiDeleteForm(path, formDataOrParams, options) {
    return submitFormMutation("DELETE", path, formDataOrParams, options);
  }

  async function submitFormMutation(method, path, formDataOrParams, options) {
    const requestOptions = options || {};
    if (requestOptions.bootstrap !== false) {
      await refreshBootstrapForMutation(requestOptions);
    }

    const body = toUrlSearchParams(formDataOrParams);
    try {
      return await fetchFormMutation(method, path, body, requestOptions);
    } catch (error) {
      if (!shouldRefreshAfterSessionError(error, requestOptions)) {
        throw error;
      }
      await refreshBootstrap(requestOptions);
      return fetchFormMutation(method, path, body, requestOptions);
    }
  }

  async function fetchFormMutation(method, path, body, requestOptions) {
    const headers = appSessionHeaders(requestOptions.headers);
    headers.set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
    const response = await fetch(apiUrl(path), {
      method,
      headers,
      body: body.toString(),
      signal: requestOptions.signal,
      credentials: "omit",
    });
    return readJsonOrThrow(response);
  }

  async function apiPostHostForm(path, formDataOrParams, options) {
    const requestOptions = options || {};
    const body = toUrlSearchParams(formDataOrParams);
    const headers = jsonHeaders(requestOptions.headers);
    headers.set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
    const response = await fetch(apiUrl(path), {
      method: "POST",
      headers,
      body: body.toString(),
      signal: requestOptions.signal,
      credentials: "omit",
    });
    return readJsonOrThrow(response);
  }

  function apiUrl(path) {
    const root = normalizeLocalRoot(
      currentBootstrap && currentBootstrap.platformApiRoot,
      defaultPlatformApiRoot
    );
    const rootUrl = new URL(root, window.location.href);
    const url = coerceApiUrl(path, rootUrl);
    if (url.origin !== rootUrl.origin || !url.pathname.startsWith(rootUrl.pathname)) {
      throw new Error("Platform API URL must stay under the bootstrap API root.");
    }
    return url;
  }

  function queueSnapshot(options) {
    const snapshotOptions = options || {};
    const params = {
      page: snapshotOptions.page || "downloads",
    };
    if (snapshotOptions.sortBy) {
      params.sortBy = snapshotOptions.sortBy;
    }
    if (snapshotOptions.reversed) {
      params.reversed = "true";
    }
    if (snapshotOptions.advancedMode != null) {
      params.advancedMode = snapshotOptions.advancedMode ? "true" : "false";
    }
    return apiGet("queue", { params, signal: snapshotOptions.signal });
  }

  function directDownload(formDataOrParams, options) {
    return apiPostForm("queue/downloads", formDataOrParams, options);
  }

  function queueMutate(path, formDataOrParams, options) {
    if (typeof path !== "string" || !path.startsWith("queue/")) {
      throw new Error("Queue mutation paths must start with queue/.");
    }
    return apiPostForm(path, formDataOrParams, options);
  }

  function insertFile(formDataOrParams, options) {
    return apiPostForm("queue/inserts/file", formDataOrParams, options);
  }

  function insertDirectory(formDataOrParams, options) {
    return apiPostForm("queue/inserts/directory", formDataOrParams, options);
  }

  function fetchText(uriOrOptions, options) {
    return fetchContent("text", uriOrOptions, options);
  }

  function fetchBase64(uriOrOptions, options) {
    return fetchContent("base64", uriOrOptions, options);
  }

  function listContentSubscriptions(options) {
    return apiGet("content/subscriptions", options);
  }

  function createContentSubscription(options) {
    const source = requireOptionsObject(options, "Content subscription options");
    return apiPostForm(
      "content/subscriptions",
      normalizeContentSubscriptionCreate(source),
      requestOptionsFrom(source)
    );
  }

  function getContentSubscription(subscriptionIdOrOptions, options) {
    const request = contentSubscriptionRequest(
      subscriptionIdOrOptions,
      options,
      "Content subscription id"
    );
    return apiGet(`content/subscriptions/${encodeURIComponent(request.subscriptionId)}`, request.options);
  }

  function refreshContentSubscription(subscriptionIdOrOptions, options) {
    const request = contentSubscriptionRequest(
      subscriptionIdOrOptions,
      options,
      "Content subscription id"
    );
    return apiPostForm(
      `content/subscriptions/${encodeURIComponent(request.subscriptionId)}/refresh`,
      {},
      request.options
    );
  }

  function pauseContentSubscription(subscriptionIdOrOptions, options) {
    const request = contentSubscriptionRequest(
      subscriptionIdOrOptions,
      options,
      "Content subscription id"
    );
    return apiPostForm(
      `content/subscriptions/${encodeURIComponent(request.subscriptionId)}/pause`,
      {},
      request.options
    );
  }

  function resumeContentSubscription(subscriptionIdOrOptions, options) {
    const request = contentSubscriptionRequest(
      subscriptionIdOrOptions,
      options,
      "Content subscription id"
    );
    return apiPostForm(
      `content/subscriptions/${encodeURIComponent(request.subscriptionId)}/resume`,
      {},
      request.options
    );
  }

  function removeContentSubscription(subscriptionIdOrOptions, options) {
    const request = contentSubscriptionRequest(
      subscriptionIdOrOptions,
      options,
      "Content subscription id"
    );
    return apiDeleteForm(
      `content/subscriptions/${encodeURIComponent(request.subscriptionId)}`,
      {},
      request.options
    );
  }

  function appDataStatus(options) {
    return apiGet("app-data/status", options).then((response) => unwrapField(response, "status"));
  }

  function listAppDataNamespaces(options) {
    return apiGet("app-data/namespaces", options).then((response) =>
      unwrapField(response, "namespaces")
    );
  }

  function getAppDataNamespace(namespace, options) {
    const path = `app-data/namespaces/${encodeURIComponent(appDataSegment(namespace, "namespace"))}`;
    return apiGet(path, options).then((response) => unwrapField(response, "namespace"));
  }

  function migrateAppDataNamespace(namespace, options) {
    const source = requireOptionsObject(options, "App-data schema migration options");
    return apiPostForm(
      `app-data/namespaces/${encodeURIComponent(appDataSegment(namespace, "namespace"))}/schema`,
      normalizeAppDataMigration(source),
      requestOptionsFrom(source)
    ).then((response) => unwrapField(response, "namespace"));
  }

  function clearAppDataNamespace(namespace, options) {
    return apiDeleteForm(
      `app-data/namespaces/${encodeURIComponent(appDataSegment(namespace, "namespace"))}`,
      {},
      options
    ).then((response) => unwrapField(response, "namespace"));
  }

  function listAppDataRecords(options) {
    const source = options && typeof options === "object" ? options : {};
    const requestOptions = requestOptionsFrom(source);
    requestOptions.params = normalizeAppDataRecordListQuery(source);
    return apiGet("app-data/records", requestOptions);
  }

  function getAppDataRecord(namespace, key, options) {
    return apiGet(
      `app-data/records/${encodeURIComponent(appDataSegment(namespace, "namespace"))}/${encodeURIComponent(
        appDataSegment(key, "key")
      )}`,
      options
    ).then((response) => unwrapField(response, "record"));
  }

  function putAppDataRecord(options) {
    const source = requireOptionsObject(options, "App-data record options");
    return apiPostForm(
      "app-data/records",
      normalizeAppDataRecordPut(source),
      requestOptionsFrom(source)
    ).then((response) => unwrapField(response, "record"));
  }

  function removeAppDataRecord(namespace, key, options) {
    return apiDeleteForm(
      `app-data/records/${encodeURIComponent(appDataSegment(namespace, "namespace"))}/${encodeURIComponent(
        appDataSegment(key, "key")
      )}`,
      {},
      options
    ).then((response) => unwrapField(response, "record"));
  }

  function putAppDataJson(options) {
    const source = requireOptionsObject(options, "App-data JSON record options");
    const record = Object.assign({}, source, {
      contentType: source.contentType || "application/json",
      valueJson: appDataJsonString(source.value),
    });
    delete record.value;
    return putAppDataRecord(record);
  }

  async function getAppDataJson(namespace, key, options) {
    const record = await getAppDataRecord(namespace, key, options);
    const json =
      typeof record.valueText === "string"
        ? record.valueText
        : utf8FromBase64(record.valueBase64 || "");
    return JSON.parse(json);
  }

  function exportAppData(options) {
    const source = options && typeof options === "object" ? options : {};
    const requestOptions = requestOptionsFrom(source);
    requestOptions.params = normalizeAppDataExportQuery(source);
    return apiGet("app-data/export", requestOptions).then((response) =>
      unwrapField(response, "export")
    );
  }

  function importAppData(payload, options) {
    const source = options && typeof options === "object" ? options : {};
    const params = new URLSearchParams();
    params.set("payloadBase64", appDataImportPayloadBase64(payload));
    copyStringParam(source, params, "mode");
    return apiPostForm("app-data/import", params, requestOptionsFrom(source)).then((response) =>
      unwrapField(response, "import")
    );
  }

  function listAppServices(options) {
    return apiGet("app-services", options);
  }

  function getAppService(providerAppId, serviceId, options) {
    return apiGet(
      `app-services/${encodeURIComponent(appServiceSegment(providerAppId, "providerAppId"))}/services/${encodeURIComponent(
        appServiceSegment(serviceId, "serviceId")
      )}`,
      options
    );
  }

  function listAppServiceGrants(options) {
    return apiGet("app-services/grants", options);
  }

  function listAppServiceDependencies(options) {
    return apiGet("app-services/dependencies", options);
  }

  function getAppServiceDependencies(consumerAppId, options) {
    const encodedConsumerAppId = encodeURIComponent(appServiceSegment(consumerAppId, "consumerAppId"));
    return apiGet(`app-services/dependencies/consumers/${encodedConsumerAppId}`, options);
  }

  function listAppServiceBundles(options) {
    return apiGet("app-services/grant-bundles", options);
  }

  function requestAppServiceBundle(request, options) {
    const source = requireOptionsObject(request, "App-service grant-bundle request");
    return apiPostForm(
      "app-services/grant-bundles",
      normalizeAppServiceBundleRequest(source),
      options || requestOptionsFrom(source)
    );
  }

  function approveAppServiceBundle(bundleIdOrOptions, options) {
    return mutateAppServiceBundle(bundleIdOrOptions, "approve", options);
  }

  function rejectAppServiceBundle(bundleIdOrOptions, options) {
    return mutateAppServiceBundle(bundleIdOrOptions, "reject", options);
  }

  function renewAppServiceBundle(bundleIdOrOptions, options) {
    return mutateAppServiceBundle(bundleIdOrOptions, "renew", options);
  }

  function mutateAppServiceBundle(bundleIdOrOptions, action, options) {
    const source =
      typeof bundleIdOrOptions === "string"
        ? options || {}
        : Object.assign({}, bundleIdOrOptions, options || {});
    const bundleId =
      typeof bundleIdOrOptions === "string"
        ? bundleIdOrOptions
        : appServiceBundleId(source);
    return apiPostHostForm(
      `app-services/grant-bundles/${encodeURIComponent(trimmedRequired(bundleId, "bundleId"))}/${action}`,
      normalizeAppServiceBundleMutation(source),
      requestOptionsFrom(source)
    );
  }

  function requestAppServiceGrant(request, options) {
    const source = requireOptionsObject(request, "App-service grant request");
    return apiPostForm(
      "app-services/grants",
      normalizeAppServiceGrantRequest(source),
      options || requestOptionsFrom(source)
    );
  }

  function revokeAppServiceGrant(grantIdOrOptions, options) {
    const grantId =
      typeof grantIdOrOptions === "string"
        ? grantIdOrOptions
        : appServiceGrantId(grantIdOrOptions);
    return apiPostForm(
      `app-services/grants/${encodeURIComponent(trimmedRequired(grantId, "grantId"))}/revoke`,
      {},
      options || requestOptionsFrom(grantIdOrOptions)
    );
  }

  function invokeAppService(providerAppId, serviceId, request, options) {
    const source = requireOptionsObject(request, "App-service invocation");
    return apiPostForm(
      `app-services/${encodeURIComponent(appServiceSegment(providerAppId, "providerAppId"))}/services/${encodeURIComponent(
        appServiceSegment(serviceId, "serviceId")
      )}/invoke`,
      normalizeAppServiceInvocation(source),
      options || requestOptionsFrom(source)
    );
  }

  function insertAppDocument(options) {
    const source = requireOptionsObject(options, "App document insert options");
    return apiPostForm(
      "queue/inserts/app-document",
      normalizeAppDocumentInsert(source),
      requestOptionsFrom(source)
    );
  }

  function insertPlainText(options) {
    const source = requireOptionsObject(options, "Plain-text insert options");
    if (typeof source.text !== "string") {
      throw new Error("Plain-text content is required.");
    }
    if (new TextEncoder().encode(source.text).length > 65536) {
      throw new Error("Plain-text content exceeds the document limit.");
    }
    const params = new URLSearchParams();
    params.set("documentBase64", utf8Base64(source.text));
    params.set("contentType", "text/plain; charset=utf-8");
    params.set("insertUri", "CHK@");
    params.set("targetFilename", "draft.txt");
    params.set("compatibilityMode", "COMPAT_CURRENT");
    params.set("compress", "true");
    copyStringParam(source, params, "identifier");
    return apiPostForm("queue/inserts/app-document", params, requestOptionsFrom(source));
  }

  function listVaultIdentities(options) {
    return apiGet("app-vault/identities", options);
  }

  function getVaultIdentity(identityId, options) {
    return apiGet(`app-vault/identities/${encodeURIComponent(vaultPathSegment(identityId))}`, options);
  }

  function createVaultIdentity(options) {
    const source = options && typeof options === "object" ? options : {};
    return apiPostForm(
      "app-vault/identities",
      normalizeVaultIdentityCreateOptions(source),
      requestOptionsFrom(source)
    );
  }

  function createProfileDocument(identityId, profile, options) {
    return apiPostForm(
      `app-vault/identities/${encodeURIComponent(vaultPathSegment(identityId))}/profile-document`,
      normalizeProfileDocument(profile),
      options
    );
  }

  function createSocialMessageDocument(identityIdOrOptions, message, options) {
    let identityId = identityIdOrOptions;
    let source = message;
    let requestOptions = options;
    if (
      identityIdOrOptions &&
      typeof identityIdOrOptions === "object" &&
      !Array.isArray(identityIdOrOptions) &&
      typeof identityIdOrOptions.entries !== "function"
    ) {
      source = identityIdOrOptions;
      identityId = source.identityId || source.authorIdentity || source.authorIdentityId;
      requestOptions = requestOptionsFrom(source);
    }
    const request = requireOptionsObject(source, "Social message document");
    return apiPostForm(
      `app-vault/identities/${encodeURIComponent(vaultPathSegment(identityId))}/social-message`,
      normalizeSocialMessageDocument(request),
      requestOptions || requestOptionsFrom(request)
    ).then(normalizeSocialMessageResponse);
  }

  function normalizeSocialMessageResponse(response) {
    if (
      response &&
      response.socialMessage &&
      response.socialMessage.socialMessage &&
      typeof response.socialMessage === "object" &&
      !Array.isArray(response.socialMessage)
    ) {
      return Object.assign({}, response.socialMessage, {
        socialMessage: response.socialMessage.socialMessage,
      });
    }
    return response;
  }

  function listVaultGrants(options) {
    return apiGet("app-vault/grants", options);
  }

  function requestVaultGrant(request, options) {
    return apiPostForm("app-vault/grants/request", normalizeVaultGrantRequest(request), options);
  }

  async function publishProfile(options) {
    const source = requireOptionsObject(options, "Profile publish options");
    const requestOptions = requestOptionsFrom(source);
    const profileDocumentResponse = await createProfileDocument(
      source.identityId,
      source.profile,
      requestOptions
    );
    const insertResponse = await insertAppDocument(
      profilePublishInsertOptions(source, profileDocumentFromResponse(profileDocumentResponse))
    );
    return {
      profileDocument: profileDocumentResponse,
      insert: insertResponse,
    };
  }

  function trustStatus(options) {
    return apiGet("trust-graph/status", options).then((response) =>
      unwrapField(response, "trustGraph")
    );
  }

  function listTrustAnchors(options) {
    return apiGet("trust-graph/anchors", options).then((response) =>
      unwrapField(response, "anchors")
    );
  }

  function addTrustAnchor(request, options) {
    return apiPostForm("trust-graph/anchors", normalizeTrustAnchor(request), options).then(
      (response) => unwrapField(response, "anchor")
    );
  }

  function removeTrustAnchor(fingerprintOrOptions, options) {
    const fingerprint =
      typeof fingerprintOrOptions === "string"
        ? fingerprintOrOptions
        : trustAnchorFingerprint(fingerprintOrOptions);
    return apiDeleteForm(
      `trust-graph/anchors/${encodeURIComponent(trimmedRequired(fingerprint, "issuerFingerprint"))}`,
      {},
      options
    ).then((response) => unwrapField(response, "anchor"));
  }

  function deprecateTrustAnchor(fingerprintOrOptions, request, options) {
    return mutateTrustAnchorLifecycle("deprecate", fingerprintOrOptions, request, options);
  }

  function revokeTrustAnchor(fingerprintOrOptions, request, options) {
    return mutateTrustAnchorLifecycle("revoke", fingerprintOrOptions, request, options);
  }

  function reactivateTrustAnchor(fingerprintOrOptions, request, options) {
    return mutateTrustAnchorLifecycle("reactivate", fingerprintOrOptions, request, options);
  }

  function mutateTrustAnchorLifecycle(action, fingerprintOrOptions, request, options) {
    const normalized = trustAnchorLifecycleRequest(fingerprintOrOptions, request, options);
    return apiPostForm(
      `trust-graph/anchors/${encodeURIComponent(normalized.fingerprint)}/${action}`,
      normalizeTrustLifecycleMutation(normalized.request),
      normalized.options
    ).then((response) => unwrapField(response, "anchor"));
  }

  function importTrustStatement(request, options) {
    return apiPostForm("trust-graph/import", normalizeTrustImport(request), options).then(
      (response) => unwrapField(response, "importResult")
    );
  }

  function previewTrustImport(request, options) {
    const params = normalizeTrustImportPreview(request);
    const route =
      params.has("uri") && !params.has("document")
        ? "trust-graph/import-preview-uri"
        : "trust-graph/import-preview";
    return apiPostForm(route, params, options).then((response) =>
      unwrapField(response, "importPreview")
    );
  }

  function importTrustUri(request, options) {
    const source = requireOptionsObject(request, "Trust URI import");
    return apiPostForm(
      "trust-graph/import-uri",
      normalizeTrustImportUri(source),
      Object.assign({}, requestOptionsFrom(source), options || {})
    ).then((response) => unwrapField(response, "importResult"));
  }

  function trustAudit(request, options) {
    const source = request && typeof request === "object" ? request : {};
    const requestOptions = Object.assign({}, requestOptionsFrom(source), options || {});
    const params = new URLSearchParams();
    copyIntegerParam(source, params, "limit");
    requestOptions.params = params;
    return apiGet("trust-graph/audit", requestOptions).then((response) =>
      unwrapField(response, "audit")
    );
  }

  function trustSubjects(options) {
    return apiGet("trust-graph/subjects", options).then((response) =>
      unwrapField(response, "subjects")
    );
  }

  function trustStatements(request, options) {
    const source = request && typeof request === "object" ? request : {};
    const requestOptions = Object.assign({}, requestOptionsFrom(source), options || {});
    requestOptions.params = normalizeTrustQuery(source, false);
    return apiGet("trust-graph/statements", requestOptions).then((response) =>
      unwrapField(response, "statements")
    );
  }

  function getTrustStatement(fingerprintOrOptions, options) {
    const request = trustStatementFingerprintRequest(fingerprintOrOptions, options);
    return apiGet(
      `trust-graph/statements/${encodeURIComponent(request.fingerprint)}`,
      request.options
    ).then((response) => unwrapField(response, "statement"));
  }

  function deprecateTrustStatement(fingerprintOrOptions, request, options) {
    return mutateTrustStatementLifecycle(
      "deprecate",
      fingerprintOrOptions,
      request,
      options
    );
  }

  function revokeTrustStatement(fingerprintOrOptions, request, options) {
    return mutateTrustStatementLifecycle("revoke", fingerprintOrOptions, request, options);
  }

  function reactivateTrustStatement(fingerprintOrOptions, request, options) {
    return mutateTrustStatementLifecycle(
      "reactivate",
      fingerprintOrOptions,
      request,
      options
    );
  }

  function mutateTrustStatementLifecycle(action, fingerprintOrOptions, request, options) {
    const normalized = trustStatementLifecycleRequest(fingerprintOrOptions, request, options);
    return apiPostForm(
      `trust-graph/statements/${encodeURIComponent(normalized.fingerprint)}/${action}`,
      normalizeTrustLifecycleMutation(normalized.request),
      normalized.options
    ).then((response) => unwrapField(response, "lifecycle"));
  }

  function trustScore(request, options) {
    const source = requireOptionsObject(request, "Trust score query");
    const requestOptions = Object.assign({}, requestOptionsFrom(source), options || {});
    requestOptions.params = normalizeTrustQuery(source, true);
    return apiGet("trust-graph/score", requestOptions).then((response) =>
      unwrapField(response, "score")
    );
  }

  async function publishTrustStatement(options) {
    const source = requireOptionsObject(options, "Trust statement publish options");
    const statement = await resolveTrustStatementForPublish(source);
    const document = trustStatementDocument({ statement });
    const requestOptions = requestOptionsFrom(source);
    const insertOptions = Object.assign({}, source, {
      document,
      contentType: trustStatementContentType,
      targetFilename: trustStatementTargetFilename,
    });
    const preparedImportResult = await importTrustStatement(
      {
        document,
        source: "local-import",
        sourceLabel: "Prepared statement for publish",
      },
      requestOptions
    );
    const queue = await insertAppDocument(insertOptions);
    let importResult = preparedImportResult;
    let localPublishImportError = null;
    try {
      importResult = await importPublishedTrustStatement(document, source, requestOptions);
    } catch (error) {
      localPublishImportError = localPublishImportErrorSummary(error);
    }
    const publication = Object.assign({}, queue || {}, {
      queue,
      importResult,
      documentFingerprint: importResult.documentFingerprint,
      payloadHash: importResult.payloadHash,
      signatureVerified: importResult.signatureVerified,
      source: importResult.source,
    });
    if (localPublishImportError) {
      publication.localPublishImportError = localPublishImportError;
    }
    return publication;
  }

  function localPublishImportErrorSummary(error) {
    const summary = {
      message: "Trust statement was queued, but local publish metadata could not be refreshed.",
    };
    if (error && typeof error.code === "string" && error.code.trim()) {
      summary.code = error.code.trim();
    }
    return summary;
  }

  function createTrustStatement(identityIdOrOptions, payload, options) {
    let identityId = identityIdOrOptions;
    let source = payload;
    let requestOptions = options;
    if (
      identityIdOrOptions &&
      typeof identityIdOrOptions === "object" &&
      !Array.isArray(identityIdOrOptions) &&
      typeof identityIdOrOptions.entries !== "function"
    ) {
      source = identityIdOrOptions;
      identityId = source.identityId || source.authorIdentity || source.authorIdentityId;
      requestOptions = requestOptionsFrom(source);
    }
    const request = requireOptionsObject(source, "Trust statement payload");
    return apiPostForm(
      `app-vault/identities/${encodeURIComponent(vaultPathSegment(identityId))}/trust-statement`,
      normalizeTrustStatementPayload(request),
      requestOptions || requestOptionsFrom(request)
    );
  }

  function importPublishedTrustStatement(document, source, requestOptions) {
    return importTrustStatement(
      {
        document,
        source: "local-publish",
        sourceLabel: source.sourceLabel || source.label || "Published statement",
      },
      requestOptions
    );
  }

  function fetchAndImportTrustStatement(request, options) {
    return importTrustUri(request, options);
  }

  function listTrustSubscriptions(options) {
    return listContentSubscriptions(options);
  }

  function createTrustSubscription(options) {
    const source = requireOptionsObject(options, "Trust subscription options");
    const request = Object.assign(
      {
        label: "Trust statement subscription",
      },
      source
    );
    return createContentSubscription(request);
  }

  function getTrustSubscription(subscriptionIdOrOptions, options) {
    return getContentSubscription(subscriptionIdOrOptions, options);
  }

  function refreshTrustSubscription(subscriptionIdOrOptions, options) {
    return refreshContentSubscription(subscriptionIdOrOptions, options);
  }

  function pauseTrustSubscription(subscriptionIdOrOptions, options) {
    return pauseContentSubscription(subscriptionIdOrOptions, options);
  }

  function resumeTrustSubscription(subscriptionIdOrOptions, options) {
    return resumeContentSubscription(subscriptionIdOrOptions, options);
  }

  function removeTrustSubscription(subscriptionIdOrOptions, options) {
    return removeContentSubscription(subscriptionIdOrOptions, options);
  }

  Object.assign(trustStatements, {
    get: getTrustStatement,
    deprecate: deprecateTrustStatement,
    revoke: revokeTrustStatement,
    reactivate: reactivateTrustStatement,
    lifecycle: Object.freeze({
      deprecate: deprecateTrustStatement,
      revoke: revokeTrustStatement,
      reactivate: reactivateTrustStatement,
    }),
  });

  async function verifyProfileDocument(value) {
    let text;
    try {
      text = typeof value === "string" ? value : JSON.stringify(value);
    } catch (error) {
      throw new Error("Profile must be JSON-serializable.");
    }
    if (typeof text !== "string") throw new Error("Profile must be JSON-serializable.");
    if (jsonDocumentByteLength(text, "Profile") > contentFormats.profileDocument.maxDocumentBytes) {
      throw new Error("Profile document is too large.");
    }
    const document = requireJsonObject(parseContentJson(text), "Profile");
    const profile = requireJsonObject(document.profile, "Profile payload");
    const identity = requireJsonObject(document.identity, "Profile identity");
    const signature = requireJsonObject(document.signature, "Profile signature");
    const fields = ["schema", "appId", "identityId", "displayName", "bio", "website", "avatarUri", "contactUri", "tags"];
    rejectUnexpectedFields(document, ["schema", "profile", "identity", "signature"], "Profile");
    rejectUnexpectedFields(profile, fields, "Profile payload");
    rejectUnexpectedFields(identity, ["identityId", "fingerprint", "algorithm", "publicKeyBase64"], "Profile identity");
    rejectUnexpectedFields(signature, ["scope", "purpose", "payloadSha256", "domainSeparatedPayload", "signatureBase64"], "Profile signature");
    if (document.schema !== "crypta.profile.v1" || profile.schema !== document.schema ||
        identity.identityId !== profile.identityId || identity.algorithm !== "Ed25519" ||
        signature.scope !== "sign.domain-separated" || signature.purpose !== "profile.publish.v1") {
      throw new Error("Profile identity or signing claims do not match.");
    }
    const payload = {};
    for (const field of fields) {
      if (!Object.hasOwn(profile, field)) continue;
      const entry = profile[field];
      if (field === "tags") {
        if (!Array.isArray(entry) || entry.length === 0 || entry.length > 16 ||
            entry.some((tag) => typeof tag !== "string" || /^[\x00-\x20]*$/.test(tag) || tag.length > 32 || /[\x00-\x1f\x7f]/.test(tag))) {
          throw new Error("Invalid profile tags.");
        }
      } else if (typeof entry !== "string" || entry.length > (field === "displayName" ? 80 : 512)) {
        throw new Error("Invalid profile field.");
      }
      if (field !== "tags" && (field === "bio" ? /[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]/ : /[\x00-\x1f\x7f]/).test(entry)) {
        throw new Error("Invalid profile control character.");
      }
      payload[field] = entry;
    }
    for (const field of ["appId", "identityId", "displayName"]) {
      if (!payload[field] || (field !== "displayName" && !/^[a-zA-Z0-9._-]+$/.test(payload[field]))) {
        throw new Error("Invalid profile binding.");
      }
    }
    const canonical = JSON.stringify(payload);
    // Validate scalar Unicode even for callers passing already parsed objects.
    parseContentJson(canonical);
    const subtle = window.crypto && window.crypto.subtle;
    if (!subtle) throw new Error("Profile signature verification unavailable.");
    const hex = async (bytes) => Array.from(new Uint8Array(await subtle.digest("SHA-256", bytes)),
      (byte) => byte.toString(16).padStart(2, "0")).join("");
    const decode = (text) => {
      if (typeof text !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) {
        throw new Error("Invalid profile signature encoding.");
      }
      return Uint8Array.from(window.atob(text), (character) => character.charCodeAt(0));
    };
    const digest = await hex(new TextEncoder().encode(canonical));
    const preimage = `CryptaAppVault:v1:${profile.appId}:${profile.identityId}:profile.publish.v1:${digest}`;
    const publicBytes = decode(identity.publicKeyBase64);
    if (signature.payloadSha256 !== digest || signature.domainSeparatedPayload !== preimage ||
        identity.fingerprint !== await hex(publicBytes)) {
      throw new Error("Profile payload or public key binding does not match.");
    }
    const key = await subtle.importKey("spki", publicBytes, { name: "Ed25519" }, false, ["verify"]);
    if (!await subtle.verify("Ed25519", key, decode(signature.signatureBase64), new TextEncoder().encode(preimage))) {
      throw new Error("Profile signature did not verify.");
    }
    return document;
  }

  function parseFeedSnapshot(value) {
    if (jsonDocumentByteLength(value, "Feed snapshot") > feedSnapshotMaxDocumentBytes) {
      throw new Error("Feed snapshot document is too large.");
    }
    const source = requireJsonObject(typeof value === "string" ? parseContentJson(value) : value, "Feed snapshot");
    rejectUnexpectedFields(
      source,
      ["type", "source", "author", "title", "updatedAt", "items", "entries"],
      "Feed snapshot"
    );
    const type = trimmedString(source.type);
    if (type !== feedSnapshotType) {
      throw new Error(`Feed snapshot type must be ${feedSnapshotType}.`);
    }
    const items = feedSnapshotItems(source);
    if (items.length > feedSnapshotMaxEntries) {
      throw new Error(`Feed snapshot must contain at most ${feedSnapshotMaxEntries} items.`);
    }

    const normalized = {
      type: feedSnapshotType,
      source: normalizeFeedSource(source.source),
      author: normalizeFeedAuthor(source.author),
    };
    copyFeedStringField(source, normalized, "title");
    copyFeedStringField(source, normalized, "updatedAt");
    normalized.items = items.map(normalizeFeedItem);
    return normalized;
  }

  async function fetchFeedSnapshot(uriOrOptions, options) {
    const response = await fetchText(uriOrOptions, options);
    const snapshot = parseFeedSnapshot(response.contentText || "");
    if (!snapshot.source.uri && response.requestedUri) {
      snapshot.source.uri = String(response.requestedUri);
    }
    if (!snapshot.source.resolvedUri && response.resolvedUri) {
      snapshot.source.resolvedUri = String(response.resolvedUri);
    }
    return { response, snapshot };
  }

  function publishFeedSnapshot(options) {
    const source = requireOptionsObject(options, "Feed publish options");
    const snapshot = parseFeedSnapshot(feedSnapshotDocument(source));
    return insertAppDocument(feedPublishInsertOptions(source, snapshot));
  }

  function sanitizeFragment(html, options) {
    const parser = new DOMParser();
    const parsed = parser.parseFromString(typeof html === "string" ? html : "", "text/html");
    sanitizeNode(parsed.body, options);
    const fragment = document.createDocumentFragment();
    fragment.append(...Array.from(parsed.body.childNodes));
    return fragment;
  }

  function sanitizeNode(root, options) {
    if (!root || typeof root.querySelectorAll !== "function") {
      return;
    }
    root.querySelectorAll(removedElementSelector).forEach((node) => {
      node.remove();
    });

    root.querySelectorAll("*").forEach((element) => {
      Array.from(element.attributes).forEach((attribute) => {
        const name = attribute.name.toLowerCase();
        if (name.startsWith("on") || name === "style" || name === "srcdoc") {
          element.removeAttribute(attribute.name);
          return;
        }
        if (urlAttributeNames.has(name) && !sameOrigin(attribute.value, options)) {
          element.removeAttribute(attribute.name);
        }
      });
    });
  }

  function sameOrigin(rawValue) {
    const value = typeof rawValue === "string" ? rawValue.trim() : "";
    if (!value || value.startsWith("#")) {
      return true;
    }
    if (value.startsWith("//")) {
      return false;
    }
    try {
      const url = new URL(value, window.location.href);
      return (
        (url.protocol === "http:" || url.protocol === "https:") &&
        url.origin === window.location.origin
      );
    } catch (error) {
      return false;
    }
  }

  function coerceApiUrl(path, rootUrl) {
    if (path instanceof URL) {
      return new URL(path.toString());
    }

    const value = path == null ? "" : String(path).trim();
    if (value.startsWith("//")) {
      throw new Error("Platform API paths must not be protocol-relative URLs.");
    }

    if (hasScheme(value)) {
      return new URL(value);
    }
    if (value.startsWith("/")) {
      return new URL(value, rootUrl);
    }
    return new URL(value, rootUrl);
  }

  function normalizeLocalRoot(value, fallback) {
    if (typeof value !== "string" || !value.trim() || value.trim().startsWith("//")) {
      return fallback;
    }
    try {
      const url = new URL(value.trim(), window.location.href);
      if (!localHttpOrigin(url) || url.search || url.hash || !url.pathname.startsWith("/api/v1/")) {
        return fallback;
      }
      url.pathname = url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
      return url.href;
    } catch (error) {
      return fallback;
    }
  }

  function localHttpOrigin(url) {
    const hostname = url.hostname.toLowerCase();
    const normalizedHostname =
      hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      (normalizedHostname === "127.0.0.1" ||
        normalizedHostname === "localhost" ||
        normalizedHostname === "::1" ||
        normalizedHostname === "0:0:0:0:0:0:0:1")
    );
  }

  function hasScheme(value) {
    return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(value);
  }

  function applySearchParams(url, params) {
    if (!params) {
      return;
    }
    appendParams(url.searchParams, params, true);
  }

  function toUrlSearchParams(source) {
    const params = new URLSearchParams();
    appendParams(params, source, false);
    return params;
  }

  function appendParams(params, source, skipEmptyValues) {
    if (!source) {
      return;
    }

    if (typeof source.entries === "function") {
      for (const [key, value] of source.entries()) {
        appendParam(params, key, value, skipEmptyValues);
      }
      return;
    }

    if (Array.isArray(source)) {
      source.forEach((entry) => {
        if (Array.isArray(entry) && entry.length >= 2) {
          appendParam(params, entry[0], entry[1], skipEmptyValues);
        }
      });
      return;
    }

    if (typeof source === "object") {
      Object.keys(source).forEach((key) => {
        const value = source[key];
        if (Array.isArray(value)) {
          value.forEach((item) => appendParam(params, key, item, skipEmptyValues));
        } else {
          appendParam(params, key, value, skipEmptyValues);
        }
      });
    }
  }

  function appendParam(params, key, value, skipEmptyValues) {
    if (value == null || (skipEmptyValues && value === "")) {
      return;
    }
    if (typeof value === "string") {
      params.append(String(key), value);
    } else if (typeof value === "number" || typeof value === "boolean") {
      params.append(String(key), String(value));
    }
  }

  function requireOptionsObject(options, description) {
    if (
      !options ||
      typeof options !== "object" ||
      Array.isArray(options) ||
      typeof options.entries === "function"
    ) {
      throw new Error(`${description} must be an object.`);
    }
    return options;
  }

  function requestOptionsFrom(source) {
    const options = {};
    copyRequestOption(source, options, "appId");
    copyRequestOption(source, options, "signal");
    copyRequestOption(source, options, "headers");
    copyRequestOption(source, options, "bootstrap");
    copyRequestOption(source, options, "force");
    copyRequestOption(source, options, "refreshBootstrap");
    return options;
  }

  function fetchContent(format, uriOrOptions, options) {
    const source = contentFetchOptions(uriOrOptions, options);
    return apiPostForm(
      "content/fetch",
      normalizeContentFetchParams(source, format),
      requestOptionsFrom(source)
    );
  }

  function contentFetchOptions(uriOrOptions, options) {
    if (typeof uriOrOptions === "string") {
      if (options != null && (typeof options !== "object" || Array.isArray(options))) {
        throw new Error("Content fetch options must be an object.");
      }
      const source = Object.assign({}, options || {});
      source.uri = uriOrOptions;
      return source;
    }
    return requireOptionsObject(uriOrOptions, "Content fetch options");
  }

  function normalizeContentFetchParams(source, format) {
    const params = new URLSearchParams();
    copyStringParam(source, params, "uri");
    copyStringParamAs(source, params, "key", "uri");
    copyPositiveIntegerParam(source, params, "maxBytes");
    copyPositiveIntegerParam(source, params, "timeoutMillis");
    copyStringParam(source, params, "purpose");
    if (!params.has("uri")) {
      throw new Error("Content fetch uri is required.");
    }
    params.set("format", format);
    return params;
  }

  function normalizeContentSubscriptionCreate(source) {
    const params = new URLSearchParams();
    copyStringParam(source, params, "uri");
    copyStringParamAs(source, params, "sourceUri", "uri");
    copyStringParam(source, params, "label");
    copyPositiveIntegerParam(source, params, "pollIntervalSeconds");
    copyPositiveIntegerParam(source, params, "maxBytes");
    copyPositiveIntegerParam(source, params, "timeoutMillis");
    if (!params.has("uri")) {
      throw new Error("Content subscription uri is required.");
    }
    if (!params.has("label")) {
      throw new Error("Content subscription label is required.");
    }
    return params;
  }

  function contentSubscriptionRequest(subscriptionIdOrOptions, options, description) {
    if (
      subscriptionIdOrOptions &&
      typeof subscriptionIdOrOptions === "object" &&
      !Array.isArray(subscriptionIdOrOptions) &&
      typeof subscriptionIdOrOptions.entries !== "function"
    ) {
      const source = subscriptionIdOrOptions;
      return {
        subscriptionId: contentSubscriptionPathSegment(
          source.subscriptionId || source.id,
          description
        ),
        options: requestOptionsFrom(source),
      };
    }
    return {
      subscriptionId: contentSubscriptionPathSegment(subscriptionIdOrOptions, description),
      options: options || {},
    };
  }

  function normalizeAppDataMigration(source) {
    const params = new URLSearchParams();
    copyPositiveIntegerParam(source, params, "fromSchemaVersion");
    copyPositiveIntegerParam(source, params, "toSchemaVersion");
    copyStringParam(source, params, "summary");
    if (!params.has("fromSchemaVersion") || !params.has("toSchemaVersion")) {
      throw new Error("App-data schema migration requires fromSchemaVersion and toSchemaVersion.");
    }
    return params;
  }

  function normalizeAppDataRecordListQuery(source) {
    const params = new URLSearchParams();
    copyStringParam(source, params, "namespace");
    copyPositiveIntegerParam(source, params, "limit");
    copyNonNegativeIntegerParam(source, params, "cursor");
    return params;
  }

  function normalizeAppDataExportQuery(source) {
    const params = new URLSearchParams();
    copyStringParam(source, params, "namespace");
    if (source.format) {
      params.set("format", String(source.format));
    }
    return params;
  }

  function normalizeAppDataRecordPut(source) {
    const params = new URLSearchParams();
    params.set("namespace", appDataSegment(source.namespace, "namespace"));
    params.set("key", appDataSegment(source.key, "key"));
    copyStringParam(source, params, "contentType");
    copyStringParam(source, params, "ifMatchSha256");
    copyStringParam(source, params, "writeIntent");
    copyStringParam(source, params, "writePreviewId");
    copyStringParam(source, params, "writeMode");
    copyStringParam(source, params, "backupReady");
    copyPositiveIntegerParam(source, params, "schemaVersion");
    if (!params.has("schemaVersion")) {
      throw new Error("App-data record schemaVersion is required.");
    }
    appendAppDataValueParam(source, params);
    return params;
  }

  function normalizeAppServiceGrantRequest(source) {
    const params = new URLSearchParams();
    params.set("providerAppId", appServiceSegment(source.providerAppId, "providerAppId"));
    params.set("serviceId", appServiceSegment(source.serviceId, "serviceId"));
    params.set("scopes", normalizeAppServiceTokenList(source.scopes, "scopes"));
    const contexts = normalizeAppServiceTokenList(source.contexts || source.context, "contexts");
    if (contexts) {
      params.set("contexts", contexts);
    }
    copyStringParam(source, params, "purpose");
    if (!params.has("purpose")) {
      throw new Error("App-service grant request purpose is required.");
    }
    return params;
  }

  function normalizeAppServiceBundleRequest(source) {
    const params = new URLSearchParams();
    if (source.consumerAppId) {
      params.set("consumerAppId", appServiceSegment(source.consumerAppId, "consumerAppId"));
    }
    if (source.bundleAlias) {
      params.set("bundleAlias", appServiceSegment(source.bundleAlias, "bundleAlias"));
    }
    copyBooleanParam(source, params, "includeOptional");
    copyStringParam(source, params, "purpose");
    return params;
  }

  function normalizeAppServiceBundleMutation(source) {
    const params = new URLSearchParams();
    copyStringParam(source, params, "form" + "Password");
    return params;
  }

  function normalizeAppServiceInvocation(source) {
    const params = new URLSearchParams();
    appendAppServiceInvocationParams(source, params);
    return params;
  }

  function appendAppServiceInvocationParams(source, params) {
    Object.keys(source).forEach((key) => {
      if (isRequestOptionKey(key)) {
        return;
      }
      const value = source[key];
      if (Array.isArray(value)) {
        value.forEach((item) => appendParam(params, key, item, true));
      } else {
        appendParam(params, key, value, true);
      }
    });
  }

  function isRequestOptionKey(key) {
    return (
      key === "appId" ||
      key === "signal" ||
      key === "headers" ||
      key === "bootstrap" ||
      key === "force" ||
      key === "refreshBootstrap"
    );
  }

  function normalizeAppServiceTokenList(value, name) {
    if (typeof value === "string" && value.trim()) {
      return value
        .split(",")
        .map((item) => appServiceSegment(item, name))
        .join(",");
    }
    if (Array.isArray(value)) {
      return value.map((item) => appServiceSegment(item, name)).join(",");
    }
    if (name === "scopes") {
      throw new Error("App-service grant request scopes are required.");
    }
    return "";
  }

  function appendAppDataValueParam(source, params) {
    const hasBase64 = typeof source.valueBase64 === "string" && source.valueBase64.trim();
    const hasText = typeof source.valueText === "string";
    const hasJson = Object.prototype.hasOwnProperty.call(source, "valueJson");
    const hasValue = Object.prototype.hasOwnProperty.call(source, "value");
    const supplied =
      (hasBase64 ? 1 : 0) + (hasText ? 1 : 0) + (hasJson ? 1 : 0) + (hasValue ? 1 : 0);
    if (supplied !== 1) {
      throw new Error("App-data record requires exactly one value field.");
    }
    if (hasBase64) {
      params.set("valueBase64", source.valueBase64.trim());
      return;
    }
    if (hasText) {
      params.set("valueText", source.valueText);
      return;
    }
    if (hasJson) {
      params.set(
        "valueJson",
        typeof source.valueJson === "string" ? source.valueJson : appDataJsonString(source.valueJson)
      );
      return;
    }
    if (typeof source.value === "string") {
      params.set("valueText", source.value);
      return;
    }
    params.set("valueJson", appDataJsonString(source.value));
  }

  function appDataImportPayloadBase64(payload) {
    if (typeof payload === "string" && payload.trim()) {
      return payload.trim();
    }
    if (payload && typeof payload === "object" && !Array.isArray(payload)) {
      const exportPayload =
        payload.export && typeof payload.export === "object" ? payload.export : payload;
      if (typeof exportPayload.payloadBase64 === "string" && exportPayload.payloadBase64.trim()) {
        return exportPayload.payloadBase64.trim();
      }
    }
    return utf8Base64(appDataJsonString(payload));
  }

  function appDataJsonString(value) {
    const json = JSON.stringify(value);
    if (typeof json !== "string") {
      throw new Error("App-data JSON value must be JSON-serializable.");
    }
    return json;
  }

  function copyRequestOption(source, target, name) {
    if (source && Object.prototype.hasOwnProperty.call(source, name)) {
      target[name] = source[name];
    }
  }

  function normalizeAppDocumentInsert(options) {
    const params = new URLSearchParams();
    copyStringParam(options, params, "insertUri");
    copyStringParam(options, params, "identifier");
    copyStringParam(options, params, "targetFilename");
    copyStringParam(options, params, "contentType");
    copyStringParam(options, params, "compatibilityMode");
    if (!params.has("contentType")) {
      copyStringParamAs(options, params, "mimeType", "contentType");
    }
    if (typeof options.compress === "boolean") {
      params.set("compress", options.compress ? "true" : "false");
    }
    const document = Object.prototype.hasOwnProperty.call(options, "document")
      ? options.document
      : options.profileDocument;
    params.set("documentBase64", jsonDocumentBase64(document, "App document"));
    return params;
  }

  function normalizeVaultIdentityCreateOptions(options) {
    const params = new URLSearchParams();
    copyStringParam(options, params, "kind");
    copyStringParam(options, params, "label");
    const scopes = normalizeVaultGrantScopes(options.scopes);
    if (scopes) {
      params.set("scopes", scopes);
    }
    return params;
  }

  function normalizeProfileDocument(profile) {
    const source = requireOptionsObject(profile, "Profile document");
    const params = new URLSearchParams();
    copyStringParam(source, params, "displayName");
    copyStringParam(source, params, "bio");
    copyStringParam(source, params, "website");
    copyStringParam(source, params, "avatarUri");
    copyStringParam(source, params, "contactUri");
    appendTagsParam(source.tags, params);
    return params;
  }

  function normalizeSocialMessageDocument(message) {
    const source = requireOptionsObject(message, "Social message document");
    const params = new URLSearchParams();
    copyStringParam(source, params, "channel");
    copyStringParam(source, params, "subject");
    copyStringParam(source, params, "body");
    copyStringParam(source, params, "format");
    copyStringParam(source, params, "replyTo");
    copyStringParam(source, params, "recipientFingerprint");
    copyStringParam(source, params, "profileUri");
    copyStringParam(source, params, "authorLabel");
    appendTagsParam(source.tags, params);
    if (!params.has("body")) {
      throw new Error("Social message document requires body.");
    }
    return params;
  }

  function appendTagsParam(tags, params) {
    if (typeof tags === "string" && tags.trim()) {
      params.set("tags", tags.trim());
      return;
    }
    if (Array.isArray(tags)) {
      const normalized = tags
        .filter((tag) => typeof tag === "string" && tag.trim())
        .map((tag) => tag.trim());
      if (normalized.length > 0) {
        params.set("tags", normalized.join(","));
      }
    }
  }

  function copyStringParam(source, params, name) {
    const value = source && source[name];
    if (typeof value === "string" && value.trim()) {
      params.set(name, value.trim());
    }
  }

  function copyBooleanParam(source, params, name) {
    if (!source || !Object.prototype.hasOwnProperty.call(source, name)) {
      return;
    }
    const value = source[name];
    if (typeof value === "boolean") {
      params.set(name, value ? "true" : "false");
      return;
    }
    if (typeof value === "string" && value.trim()) {
      const normalized = value.trim().toLowerCase();
      if (normalized !== "true" && normalized !== "false") {
        throw new Error(`${name} must be true or false.`);
      }
      params.set(name, normalized);
      return;
    }
    throw new Error(`${name} must be true or false.`);
  }

  function copyStringParamAs(source, params, sourceName, targetName) {
    const value = source && source[sourceName];
    if (typeof value === "string" && value.trim()) {
      params.set(targetName, value.trim());
    }
  }

  function copyPositiveIntegerParam(source, params, name) {
    if (!source || !Object.prototype.hasOwnProperty.call(source, name)) {
      return;
    }
    const value = source[name];
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value) || value <= 0) {
        throw new Error(`${name} must be a positive integer.`);
      }
      params.set(name, String(value));
      return;
    }
    if (typeof value === "string" && value.trim()) {
      const normalized = value.trim();
      if (!/^[1-9][0-9]*$/.test(normalized)) {
        throw new Error(`${name} must be a positive integer.`);
      }
      params.set(name, normalized);
    }
  }

  function copyNonNegativeIntegerParam(source, params, name) {
    if (!source || !Object.prototype.hasOwnProperty.call(source, name)) {
      return;
    }
    const value = source[name];
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error(`${name} must be a non-negative integer.`);
      }
      params.set(name, String(value));
      return;
    }
    if (typeof value === "string" && value.trim()) {
      const normalized = value.trim();
      if (!/^[0-9]+$/.test(normalized)) {
        throw new Error(`${name} must be a non-negative integer.`);
      }
      params.set(name, normalized);
    }
  }

  function jsonDocumentBase64(value, description) {
    let json;
    try {
      json = JSON.stringify(value);
    } catch (error) {
      throw new Error(`${description} must be JSON-serializable.`);
    }
    if (typeof json !== "string") {
      throw new Error(`${description} must be JSON-serializable.`);
    }
    return utf8Base64(json);
  }

  function utf8Base64(value) {
    if (typeof TextEncoder === "undefined" || typeof btoa !== "function") {
      throw new Error("JSON document encoding is unavailable in this browser.");
    }
    const bytes = new TextEncoder().encode(value);
    const chunkSize = 32768;
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      const chunk = bytes.subarray(offset, offset + chunkSize);
      binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary);
  }

  function utf8FromBase64(value) {
    if (typeof TextDecoder === "undefined" || typeof atob !== "function") {
      throw new Error("JSON document decoding is unavailable in this browser.");
    }
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return new TextDecoder().decode(bytes);
  }

  function profileDocumentFromResponse(response) {
    if (!response || typeof response !== "object") {
      return response;
    }
    if (response.profileDocument && typeof response.profileDocument === "object") {
      if (
        response.profileDocument.document &&
        typeof response.profileDocument.document === "object"
      ) {
        return response.profileDocument.document;
      }
      return response.profileDocument;
    }
    if (response.document && typeof response.document === "object") {
      return response.document;
    }
    return response;
  }

  function profilePublishInsertOptions(source, document) {
    const options = Object.assign({}, source, { document });
    if (!nonBlankString(options.identifier)) {
      options.identifier = `profile-${vaultPathSegment(source.identityId)}`;
    }
    if (!nonBlankString(options.targetFilename)) {
      options.targetFilename = contentFormats.profileDocument.defaultFilename;
    }
    if (!nonBlankString(options.contentType)) {
      options.contentType = contentFormats.profileDocument.contentType;
    }
    return options;
  }

  function normalizeTrustAnchor(request) {
    const source = requireOptionsObject(request, "Trust anchor");
    const params = new URLSearchParams();
    params.set("issuerFingerprint", trimmedRequired(trustAnchorFingerprint(source), "issuerFingerprint"));
    copyStringParam(source, params, "label");
    copyStringParam(source, params, "source");
    return params;
  }

  function trustAnchorFingerprint(source) {
    if (typeof source === "string") {
      return source;
    }
    if (!source || typeof source !== "object" || Array.isArray(source)) {
      throw new Error("Trust anchor issuer fingerprint is required.");
    }
    return (
      source.issuerFingerprint ||
      source.fingerprint ||
      source.identity ||
      source.identityId ||
      source.id
    );
  }

  function normalizeTrustImport(request) {
    const source = requireOptionsObject(request, "Trust import");
    const params = new URLSearchParams();
    params.set("document", trustStatementText(source));
    copyStringParam(source, params, "source");
    copyStringParam(source, params, "sourceUri");
    copyStringParamAs(source, params, "uri", "sourceUri");
    copyStringParam(source, params, "sourceLabel");
    copyStringParamAs(source, params, "label", "sourceLabel");
    copyStringParam(source, params, "subscriptionId");
    return params;
  }

  function normalizeTrustImportUri(request) {
    const source = requireOptionsObject(request, "Trust URI import");
    const params = new URLSearchParams();
    params.set("uri", trimmedRequired(source.uri || source.sourceUri, "uri"));
    copyStringParam(source, params, "sourceLabel");
    copyStringParamAs(source, params, "label", "sourceLabel");
    copyStringParam(source, params, "subscriptionId");
    copyStringParam(source, params, "expectedDocumentFingerprint");
    copyStringParamAs(source, params, "previewDocumentFingerprint", "expectedDocumentFingerprint");
    copyIntegerParam(source, params, "maxBytes");
    return params;
  }

  function normalizeTrustImportPreview(request) {
    const source = requireOptionsObject(request, "Trust import preview");
    const params = new URLSearchParams();
    const hasDocument = hasTrustStatementText(source);
    if (hasDocument) {
      params.set("document", trustStatementText(source));
      copyStringParam(source, params, "sourceUri");
      copyStringParamAs(source, params, "uri", "sourceUri");
    } else {
      copyStringParam(source, params, "uri");
      if (!params.has("uri")) {
        params.set("uri", trimmedRequired(source.sourceUri, "uri"));
      }
    }
    copyStringParam(source, params, "sourceLabel");
    copyStringParamAs(source, params, "label", "sourceLabel");
    copyStringParam(source, params, "subscriptionId");
    copyIntegerParam(source, params, "maxBytes");
    return params;
  }

  function normalizeTrustLifecycleMutation(request) {
    const source = request && typeof request === "object" && !Array.isArray(request) ? request : {};
    const params = new URLSearchParams();
    copyStringParam(source, params, "reasonCode");
    copyStringParam(source, params, "note");
    copyStringParam(source, params, "replacementUri");
    copyStringParamAs(source, params, "replacement", "replacementUri");
    return params;
  }

  function trustStatementFingerprintRequest(fingerprintOrOptions, options) {
    if (
      fingerprintOrOptions &&
      typeof fingerprintOrOptions === "object" &&
      !Array.isArray(fingerprintOrOptions) &&
      typeof fingerprintOrOptions.entries !== "function"
    ) {
      const source = fingerprintOrOptions;
      return {
        fingerprint: trustStatementFingerprint(source),
        options: Object.assign({}, requestOptionsFrom(source), options || {}),
      };
    }
    return {
      fingerprint: trimmedRequired(fingerprintOrOptions, "statementFingerprint"),
      options,
    };
  }

  function trustStatementLifecycleRequest(fingerprintOrOptions, request, options) {
    if (
      fingerprintOrOptions &&
      typeof fingerprintOrOptions === "object" &&
      !Array.isArray(fingerprintOrOptions) &&
      typeof fingerprintOrOptions.entries !== "function"
    ) {
      const source = fingerprintOrOptions;
      return {
        fingerprint: trustStatementFingerprint(source),
        request: source,
        options: Object.assign({}, requestOptionsFrom(source), request || {}),
      };
    }
    const mutation = request && typeof request === "object" ? request : {};
    return {
      fingerprint: trimmedRequired(fingerprintOrOptions, "statementFingerprint"),
      request: mutation,
      options: Object.assign({}, requestOptionsFrom(mutation), options || {}),
    };
  }

  function trustAnchorLifecycleRequest(fingerprintOrOptions, request, options) {
    if (
      fingerprintOrOptions &&
      typeof fingerprintOrOptions === "object" &&
      !Array.isArray(fingerprintOrOptions) &&
      typeof fingerprintOrOptions.entries !== "function"
    ) {
      const source = fingerprintOrOptions;
      return {
        fingerprint: trustAnchorFingerprint(source),
        request: source,
        options: Object.assign({}, requestOptionsFrom(source), request || {}),
      };
    }
    const mutation = request && typeof request === "object" ? request : {};
    return {
      fingerprint: trimmedRequired(fingerprintOrOptions, "issuerFingerprint"),
      request: mutation,
      options: Object.assign({}, requestOptionsFrom(mutation), options || {}),
    };
  }

  function trustStatementFingerprint(source) {
    if (typeof source === "string") {
      return trimmedRequired(source, "statementFingerprint");
    }
    if (!source || typeof source !== "object" || Array.isArray(source)) {
      throw new Error("Trust statement fingerprint is required.");
    }
    return trimmedRequired(
      source.statementFingerprint ||
        source.documentFingerprint ||
        source.fingerprint ||
        source.id,
      "statementFingerprint"
    );
  }

  function normalizeTrustQuery(source, requireSubject) {
    const params = new URLSearchParams();
    copyStringParam(source, params, "subjectKind");
    copyStringParamAs(source, params, "kind", "subjectKind");
    copyStringParam(source, params, "subjectUri");
    copyStringParamAs(source, params, "uri", "subjectUri");
    copyStringParamAs(source, params, "subject", "subjectUri");
    copyStringParam(source, params, "context");
    copyStringParam(source, params, "issuerFingerprint");
    if (typeof source.includeEvidence === "boolean") {
      params.set("includeEvidence", source.includeEvidence ? "true" : "false");
    }
    if (
      requireSubject &&
      (!params.has("subjectKind") || !params.has("subjectUri") || !params.has("context"))
    ) {
      throw new Error("Trust score query requires subjectKind, subjectUri, and context.");
    }
    return params;
  }

  function normalizeTrustStatementPayload(source) {
    const params = new URLSearchParams();
    copyStringParam(source, params, "subjectKind");
    copyStringParamAs(source, params, "kind", "subjectKind");
    copyStringParam(source, params, "subjectUri");
    copyStringParamAs(source, params, "uri", "subjectUri");
    copyStringParamAs(source, params, "subject", "subjectUri");
    copyStringParamAs(source, params, "subjectIdentity", "subjectUri");
    copyStringParam(source, params, "subjectFingerprint");
    copyStringParam(source, params, "context");
    copyIntegerParam(source, params, "score");
    copyIntegerParamAs(source, params, "value", "score");
    copyIntegerParam(source, params, "confidence");
    copyStringParam(source, params, "reason");
    appendTagsParam(source.tags, params);
    copyStringParam(source, params, "expiresAt");
    copyStringParam(source, params, "profileUri");
    for (const requiredName of ["subjectKind", "subjectUri", "context", "score", "confidence"]) {
      if (!params.has(requiredName)) {
        throw new Error(`Trust statement payload requires ${requiredName}.`);
      }
    }
    return params;
  }

  function trustStatementDocument(source) {
    const value = Object.prototype.hasOwnProperty.call(source, "statement")
      ? source.statement
      : Object.prototype.hasOwnProperty.call(source, "trustStatement")
        ? source.trustStatement
        : source.document;
    let current = parseJsonObject(value, "Trust statement");
    for (let depth = 0; depth < 4; depth += 1) {
      if (current.type === trustStatementType) {
        return current;
      }
      if (typeof current.trustStatement === "string") {
        current = parseJsonObject(current.trustStatement, "Trust statement");
      } else if (
        current.trustStatement &&
        typeof current.trustStatement === "object" &&
        !Array.isArray(current.trustStatement)
      ) {
        current = current.trustStatement;
      } else {
        break;
      }
    }
    return current;
  }

  async function resolveTrustStatementForPublish(source) {
    if (
      Object.prototype.hasOwnProperty.call(source, "statement") ||
      Object.prototype.hasOwnProperty.call(source, "trustStatement") ||
      Object.prototype.hasOwnProperty.call(source, "document")
    ) {
      return trustStatementDocument(source);
    }
    const identityId = source.identityId || source.authorIdentity || source.authorIdentityId;
    if (!identityId) {
      throw new Error("Trust statement publish options require identityId or statement.");
    }
    const signed = await createTrustStatement(identityId, source, requestOptionsFrom(source));
    return trustStatementDocument({ statement: signed });
  }

  function hasTrustStatementText(source) {
    return (
      Object.prototype.hasOwnProperty.call(source, "document") ||
      Object.prototype.hasOwnProperty.call(source, "trustStatement") ||
      Object.prototype.hasOwnProperty.call(source, "statement") ||
      Object.prototype.hasOwnProperty.call(source, "text")
    );
  }

  function trustStatementText(source) {
    const value = Object.prototype.hasOwnProperty.call(source, "document")
      ? source.document
      : Object.prototype.hasOwnProperty.call(source, "trustStatement")
        ? source.trustStatement
        : Object.prototype.hasOwnProperty.call(source, "statement")
          ? source.statement
          : source.text;
    if (typeof value === "string") {
      return trimmedRequired(value, "document");
    }
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return JSON.stringify(trustStatementDocument({ document: value }));
    }
    throw new Error("Trust import document is required.");
  }

  function copyIntegerParam(source, params, name) {
    copyIntegerParamAs(source, params, name, name);
  }

  function copyIntegerParamAs(source, params, sourceName, targetName) {
    if (!source || !Object.prototype.hasOwnProperty.call(source, sourceName)) {
      return;
    }
    const value = source[sourceName];
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) {
        throw new Error(`${sourceName} must be an integer.`);
      }
      params.set(targetName, String(value));
      return;
    }
    if (typeof value === "string" && value.trim()) {
      const normalized = value.trim();
      if (!/^-?[0-9]+$/.test(normalized)) {
        throw new Error(`${sourceName} must be an integer.`);
      }
      params.set(targetName, normalized);
    }
  }

  function trimmedRequired(value, name) {
    if (typeof value !== "string" || !value.trim()) {
      throw new Error(`${name} is required.`);
    }
    return value.trim();
  }

  function unwrapField(response, fieldName) {
    return response &&
      typeof response === "object" &&
      !Array.isArray(response) &&
      Object.prototype.hasOwnProperty.call(response, fieldName)
      ? response[fieldName]
      : response;
  }

  function parseJsonObject(value, description) {
    const source = typeof value === "string" ? parseJsonString(value, description) : value;
    return requireJsonObject(source, description);
  }

  function requireJsonObject(source, description) {
    if (!source || typeof source !== "object" || Array.isArray(source)) {
      throw new Error(`${description} must be a JSON object.`);
    }
    return source;
  }

  // JSON.parse supplies the grammar; this lexical pass rejects ambiguous members and
  // excessive nesting before materialization. String tokens use the native JSON decoder.
  function contentJsonError(message) {
    const error = new Error(message);
    error.code = "content_format_ambiguous_json";
    return error;
  }

  function parseContentJson(text) {
    const tokens = text.match(/"(?:[^"\\\x00-\x1f]|\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4}))*"|[{}\[\]:,]|[^\s{}\[\]:,"]+/g) || [];
    const stack = [];
    for (let index = 0; index < tokens.length; index += 1) {
      const token = tokens[index];
      if (token === "{" || token === "[") {
        stack.push(token === "{" ? new Set() : null);
        if (stack.length > 16) throw contentJsonError("Content JSON nesting exceeds limit.");
      } else if (token === "}" || token === "]") {
        stack.pop();
      } else if (token.startsWith('"')) {
        const value = JSON.parse(token);
        for (let offset = 0; offset < value.length; offset += 1) {
          const unit = value.charCodeAt(offset);
          if (unit >= 0xd800 && unit <= 0xdbff) {
            const low = value.charCodeAt(++offset);
            if (!(low >= 0xdc00 && low <= 0xdfff)) throw contentJsonError("Unpaired surrogate.");
          } else if (unit >= 0xdc00 && unit <= 0xdfff) throw contentJsonError("Unpaired surrogate.");
        }
        if (tokens[index + 1] === ":") {
          const keys = stack[stack.length - 1];
          if (keys && keys.has(value)) throw contentJsonError("Duplicate content JSON field.");
          if (keys) keys.add(value);
        }
      }
    }
    try {
      return JSON.parse(text);
    } catch (error) {
      if (text.trim().startsWith("{")) throw contentJsonError("Invalid content JSON.");
      throw error;
    }
  }

  function parseJsonString(value, description) {
    try {
      return JSON.parse(value);
    } catch (error) {
      throw new Error(`${description} must be valid JSON.`);
    }
  }

  function feedSnapshotItems(source) {
    if (Object.hasOwn(source, "items") && Object.hasOwn(source, "entries")) {
      throw new Error("Feed snapshot cannot contain both items and entries.");
    }
    if (Array.isArray(source.items)) {
      return source.items;
    }
    if (Array.isArray(source.entries)) {
      return source.entries;
    }
    throw new Error("Feed snapshot items must be an array.");
  }

  function normalizeFeedSource(source) {
    const value = source === undefined ? {} : requireJsonObject(source, "Feed snapshot source");
    rejectUnexpectedFields(value, ["uri", "resolvedUri"], "Feed snapshot source");
    const normalized = {};
    copyFeedStringField(value, normalized, "uri");
    copyFeedStringField(value, normalized, "resolvedUri");
    return normalized;
  }

  function normalizeFeedAuthor(author) {
    const value = author === undefined ? {} : requireJsonObject(author, "Feed snapshot author");
    rejectUnexpectedFields(value, ["name", "profileUri"], "Feed snapshot author");
    const normalized = {};
    copyFeedStringField(value, normalized, "name");
    copyFeedStringField(value, normalized, "profileUri");
    return normalized;
  }

  function normalizeFeedItem(item) {
    const source = parseJsonObject(item, "Feed item");
    rejectUnexpectedFields(
      source,
      ["id", "title", "summary", "uri", "publishedAt", "tags"],
      "Feed item"
    );
    const normalized = {};
    copyFeedStringField(source, normalized, "id");
    copyFeedStringField(source, normalized, "title");
    copyFeedStringField(source, normalized, "summary");
    copyFeedStringField(source, normalized, "uri");
    copyFeedStringField(source, normalized, "publishedAt");
    const tags = normalizeFeedTags(source.tags);
    if (tags.length > 0) {
      normalized.tags = tags;
    }
    return normalized;
  }

  function normalizeFeedTags(tags) {
    const source =
      typeof tags === "string"
        ? tags.split(",")
        : Array.isArray(tags)
          ? tags
        : [];
    const unique = new Set();
    source.forEach((tag) => {
      const normalized = trimmedString(tag);
      if (normalized) {
        unique.add(normalized);
      }
    });
    return Array.from(unique).sort();
  }

  function copyFeedStringField(source, target, name) {
    if (Object.hasOwn(source, name) && typeof source[name] !== "string") {
      throw new Error(`Feed snapshot ${name} must be text.`);
    }
    const value = trimmedString(source[name]);
    if (value) {
      target[name] = value;
    }
  }

  function rejectUnexpectedFields(object, allowedFields, description) {
    const allowed = new Set(allowedFields);
    for (const field of Object.keys(object)) {
      if (!allowed.has(field)) {
        throw new Error(`${description} field ${field} is not supported.`);
      }
    }
  }

  function jsonDocumentByteLength(value, description) {
    if (typeof value === "string") {
      return utf8ByteLength(value);
    }
    let json;
    try {
      json = JSON.stringify(value);
    } catch (error) {
      throw new Error(`${description} must be JSON-serializable.`);
    }
    if (typeof json !== "string") {
      throw new Error(`${description} must be JSON-serializable.`);
    }
    return utf8ByteLength(json);
  }

  function utf8ByteLength(value) {
    const text = typeof value === "string" ? value : String(value || "");
    if (typeof TextEncoder !== "undefined") {
      return new TextEncoder().encode(text).length;
    }
    if (typeof Blob !== "undefined") {
      return new Blob([text]).size;
    }
    return text.length;
  }

  function trimmedString(value) {
    return typeof value === "string" ? value.trim() : "";
  }

  function feedSnapshotDocument(source) {
    if (Object.prototype.hasOwnProperty.call(source, "snapshot")) {
      return source.snapshot;
    }
    if (Object.prototype.hasOwnProperty.call(source, "feed")) {
      return source.feed;
    }
    if (Object.prototype.hasOwnProperty.call(source, "document")) {
      return source.document;
    }
    throw new Error("Feed publish options must include a snapshot.");
  }

  function feedPublishInsertOptions(source, snapshot) {
    const options = Object.assign({}, source, { document: snapshot });
    options.contentType = feedSnapshotContentType;
    options.targetFilename = feedSnapshotTargetFilename;
    return options;
  }

  function nonBlankString(value) {
    return typeof value === "string" && !!value.trim();
  }

  function jsonHeaders(headers) {
    const result = new Headers(headers || {});
    if (!result.has("Accept")) {
      result.set("Accept", "application/json");
    }
    return result;
  }

  function appSessionHeaders(headers) {
    const result = jsonHeaders(headers);
    if (!currentBrowserSessionToken) {
      throw new Error("App browser session is unavailable; reload the app UI.");
    }
    result.set("X-Crypta-App-Session", currentBrowserSessionToken);
    return result;
  }

  async function ensureBootstrap(options) {
    if (currentBootstrap && currentBrowserSessionToken && !(options && options.force)) {
      return currentBootstrap;
    }
    if (currentBootstrap && !currentBrowserSessionToken && !(options && options.force)) {
      return refreshBootstrap(options);
    }
    return loadBootstrap(options);
  }

  async function refreshBootstrap(options) {
    const appId = explicitAppId(options) || currentAppId || inferAppId();
    if (!appId) {
      return loadBootstrap(Object.assign({}, options, { force: true }));
    }
    return loadBootstrap(Object.assign({}, options, { appId, force: true }));
  }

  async function refreshBootstrapForMutation(options) {
    if (options && options.refreshBootstrap === false) {
      return ensureBootstrap(options);
    }
    if (!(options && options.force) && currentBrowserSessionLive()) {
      return ensureBootstrap(options);
    }
    return refreshBootstrap(options);
  }

  function currentBrowserSessionLive() {
    if (!currentBootstrap || !currentBrowserSessionToken) {
      return false;
    }
    const expiresAt = browserSessionExpiresAtMillis(currentBootstrap);
    return expiresAt == null || expiresAt > Date.now();
  }

  function browserSessionExpiresAtMillis(bootstrap) {
    const value =
      bootstrap && typeof bootstrap.browserSessionExpiresAt === "string"
        ? bootstrap.browserSessionExpiresAt.trim()
        : "";
    if (!value) {
      return null;
    }
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }

  async function readJsonOrThrow(response) {
    const data = await readJson(response);
    if (!response.ok) {
      throw responseError(data, response);
    }
    return data;
  }

  async function readJson(response) {
    return response.json().catch(() => ({}));
  }

  function responseErrorMessage(data, response) {
    const bodyMessage = responseBodyMessage(data);
    if (bodyMessage) {
      return bodyMessage;
    }
    if (response) {
      const status = response.status ? String(response.status) : "HTTP error";
      return response.statusText ? `${status} ${response.statusText}` : status;
    }
    return "Unknown error";
  }

  function responseError(data, response) {
    const code = responseErrorCode(data);
    const message =
      code === "invalid_app_browser_session"
        ? "App browser session expired; reload the app UI."
        : code === "origin_mismatch"
          ? "App browser session origin mismatch; reopen the app from Web Shell."
        : responseErrorMessage(data, response);
    if (code === "invalid_app_browser_session") {
      currentBrowserSessionToken = "";
    }
    const error = new Error(message);
    if (code) {
      error.code = code;
    }
    if (code === "invalid_app_browser_session") {
      error.sessionRefreshRequired = true;
    }
    return error;
  }

  function shouldRefreshAfterSessionError(error, options) {
    return (
      error &&
      error.code === "invalid_app_browser_session" &&
      !(options && options.bootstrap === false)
    );
  }

  function responseErrorCode(data) {
    if (data && typeof data === "object" && data.error && typeof data.error.code === "string") {
      return data.error.code;
    }
    return "";
  }

  function responseBodyMessage(data) {
    if (!data || typeof data !== "object") {
      return "";
    }
    if (typeof data.error === "string" && data.error.trim()) {
      return data.error.trim();
    }
    if (data.error && typeof data.error.message === "string" && data.error.message.trim()) {
      return data.error.message.trim();
    }
    if (typeof data.message === "string" && data.message.trim()) {
      return data.message.trim();
    }
    if (typeof data.detail === "string" && data.detail.trim()) {
      return data.detail.trim();
    }
    return "";
  }

  function errorMessage(error) {
    if (error instanceof Error && error.message) {
      return error.message;
    }
    if (typeof error === "string" && error) {
      return error;
    }
    const message = responseBodyMessage(error);
    return message || "Unknown error";
  }

  function explicitAppId(options) {
    const appId = options && typeof options.appId === "string" ? options.appId.trim() : "";
    return appId || "";
  }

  function inferAppId() {
    const segments = window.location.pathname.split("/");
    if (segments.length < 3 || segments[1] !== "apps") {
      return null;
    }
    try {
      return decodeURIComponent(segments[2]);
    } catch (error) {
      return null;
    }
  }

  function bootstrapUrls(appId) {
    const rootBootstrapUrl = `/${bootstrapResourcePath}`;
    if (!appId || !legacyAdminAppPath(appId)) {
      return [rootBootstrapUrl];
    }
    return [rootBootstrapUrl, `/apps/${encodeURIComponent(appId)}/${bootstrapResourcePath}`];
  }

  function bootstrapMatchesRequest(bootstrap, appId) {
    return !appId || (bootstrap && bootstrap.appId === appId);
  }

  function legacyAdminAppPath(appId) {
    const segments = window.location.pathname.split("/");
    if (segments.length < 3 || segments[1] !== "apps") {
      return false;
    }
    try {
      return normalizeAppId(decodeURIComponent(segments[2])) === appId;
    } catch (error) {
      return false;
    }
  }

  function normalizeAppId(appId) {
    if (typeof appId !== "string") {
      throw new Error("Cryptad app id must be a string.");
    }
    const normalized = appId.trim().toLowerCase();
    if (!appIdPattern.test(normalized)) {
      throw new Error("Cryptad app id must be one normalized local path segment.");
    }
    return normalized;
  }

  function vaultPathSegment(value) {
    if (typeof value !== "string") {
      throw new Error("Vault identity id must be a string.");
    }
    const normalized = value.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9._-]{0,191}$/.test(normalized)) {
      throw new Error("Vault identity id must be one normalized local path segment.");
    }
    return normalized;
  }

  function contentSubscriptionPathSegment(value, description) {
    if (typeof value !== "string") {
      throw new Error(`${description} must be a string.`);
    }
    const normalized = value.trim().toLowerCase();
    if (!/^[a-z0-9](?:[a-z0-9._-]{0,190}[a-z0-9])?$/.test(normalized)) {
      throw new Error(`${description} must be one normalized local path segment.`);
    }
    return normalized;
  }

  function appDataSegment(value, description) {
    if (typeof value !== "string") {
      throw new Error(`App-data ${description} must be a string.`);
    }
    const normalized = value.trim().toLowerCase();
    if (!/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(normalized)) {
      throw new Error(`App-data ${description} must be one normalized local path segment.`);
    }
    return normalized;
  }

  function appServiceSegment(value, description) {
    if (typeof value !== "string") {
      throw new Error(`App-service ${description} must be a string.`);
    }
    const normalized = value.trim().toLowerCase();
    if (!/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(normalized)) {
      throw new Error(`App-service ${description} must be one normalized local path segment.`);
    }
    return normalized;
  }

  function appServiceGrantId(source) {
    if (!source || typeof source !== "object" || Array.isArray(source)) {
      throw new Error("App-service grant id is required.");
    }
    return source.grantId || source.id;
  }

  function appServiceBundleId(source) {
    if (!source || typeof source !== "object" || Array.isArray(source)) {
      throw new Error("App-service grant-bundle id is required.");
    }
    return source.bundleId || source.id;
  }

  function normalizeVaultGrantRequest(request) {
    const source = request && typeof request === "object" ? request : {};
    const params = {
      identityId: vaultPathSegment(source.identityId),
      scopes: normalizeVaultGrantScopes(source.scopes),
    };
    if (typeof source.reason === "string" && source.reason.trim()) {
      params.reason = source.reason.trim();
    }
    return params;
  }

  function normalizeVaultGrantScopes(scopes) {
    if (typeof scopes === "string") {
      return scopes
        .split(",")
        .map((scope) => normalizeVaultGrantScope(scope))
        .join(",");
    }
    if (Array.isArray(scopes)) {
      return scopes.map((scope) => normalizeVaultGrantScope(scope)).join(",");
    }
    return "";
  }

  function normalizeVaultGrantScope(scope) {
    if (typeof scope !== "string") {
      throw new Error("Vault grant scopes must be strings.");
    }
    const normalized = scope.trim().toLowerCase();
    if (
      normalized !== "metadata.read" &&
      normalized !== "sign.domain-separated" &&
      normalized !== "publish.content" &&
      normalized !== "publish.profile" &&
      normalized !== "use.external-reference"
    ) {
      throw new Error("Unsupported vault grant scope.");
    }
    return normalized;
  }

  function sanitizeBootstrap(data) {
    const source = data && typeof data === "object" ? data : {};
    const bootstrap = {};
    copyStringField(source, bootstrap, "appId");
    copyStringField(source, bootstrap, "name");
    copyStringField(source, bootstrap, "uiRoot");
    copyStringField(source, bootstrap, "assetRoot");
    copyStringField(source, bootstrap, "platformApiRoot");
    copyStringField(source, bootstrap, "shellRoot");
    copyStringField(source, bootstrap, "uiOrigin");
    copyStringField(source, bootstrap, "uiOriginMode");
    copyStringField(source, bootstrap, "uiOriginStatus");
    copyStringField(source, bootstrap, "sameOriginFallbackUrl");
    copyStringField(source, bootstrap, "browserSessionExpiresAt");
    return bootstrap;
  }

  function sessionTokenFromBootstrap(data) {
    return data && typeof data.browserSessionToken === "string"
      ? data.browserSessionToken.trim()
      : "";
  }

  function copyStringField(source, target, name) {
    if (typeof source[name] === "string") {
      target[name] = source[name];
    }
  }

  function copyBootstrap(bootstrap) {
    return Object.assign({}, bootstrap);
  }

  window.CryptaPlatform = Object.freeze({
    bootstrap: Object.freeze({
      load: loadBootstrap,
      current,
    }),
    app: Object.freeze({
      currentId,
    }),
    contentFormats,
    api: Object.freeze({
      url: apiUrl,
      get: apiGet,
      postForm: apiPostForm,
      deleteForm: apiDeleteForm,
      errorMessage,
    }),
    queue: Object.freeze({
      snapshot: queueSnapshot,
      directDownload,
      mutate: queueMutate,
    }),
    content: Object.freeze({
      fetchText,
      fetchBase64,
      insertFile,
      insertDirectory,
      insertAppDocument,
      insertPlainText,
      subscriptions: Object.freeze({
        list: listContentSubscriptions,
        create: createContentSubscription,
        get: getContentSubscription,
        refresh: refreshContentSubscription,
        pause: pauseContentSubscription,
        resume: resumeContentSubscription,
        remove: removeContentSubscription,
      }),
    }),
    data: Object.freeze({
      status: appDataStatus,
      export: exportAppData,
      import: importAppData,
      namespaces: Object.freeze({
        list: listAppDataNamespaces,
        get: getAppDataNamespace,
        migrate: migrateAppDataNamespace,
        clear: clearAppDataNamespace,
      }),
      records: Object.freeze({
        list: listAppDataRecords,
        get: getAppDataRecord,
        put: putAppDataRecord,
        remove: removeAppDataRecord,
        putJson: putAppDataJson,
        getJson: getAppDataJson,
      }),
    }),
    mail: Object.freeze({ command: mailCommand }),
    services: Object.freeze({
      list: listAppServices,
      get: getAppService,
      dependencies: Object.freeze({
        list: listAppServiceDependencies,
        get: getAppServiceDependencies,
      }),
      bundles: Object.freeze({
        list: listAppServiceBundles,
        request: requestAppServiceBundle,
        approve: approveAppServiceBundle,
        reject: rejectAppServiceBundle,
        renew: renewAppServiceBundle,
      }),
      grants: Object.freeze({
        list: listAppServiceGrants,
        request: requestAppServiceGrant,
        revoke: revokeAppServiceGrant,
      }),
      invoke: invokeAppService,
    }),
    vault: Object.freeze({
      identities: Object.freeze({
        list: listVaultIdentities,
        get: getVaultIdentity,
        create: createVaultIdentity,
        createProfileDocument,
        createSocialMessageDocument,
        createTrustStatement,
      }),
      grants: Object.freeze({
        list: listVaultGrants,
        request: requestVaultGrant,
      }),
    }),
    profile: Object.freeze({
      verifyDocument: verifyProfileDocument,
      publish: publishProfile,
    }),
    feed: Object.freeze({
      parseSnapshot: parseFeedSnapshot,
      fetchSnapshot: fetchFeedSnapshot,
      publishSnapshot: publishFeedSnapshot,
    }),
    trust: Object.freeze({
      status: trustStatus,
      anchors: Object.freeze({
        list: listTrustAnchors,
        add: addTrustAnchor,
        remove: removeTrustAnchor,
        deprecate: deprecateTrustAnchor,
        revoke: revokeTrustAnchor,
        reactivate: reactivateTrustAnchor,
      }),
      previewImport: previewTrustImport,
      importStatement: importTrustStatement,
      importUri: importTrustUri,
      audit: Object.freeze({
        list: trustAudit,
      }),
      subjects: trustSubjects,
      statements: trustStatements,
      score: trustScore,
      publishStatement: publishTrustStatement,
      exchange: Object.freeze({
        publish: publishTrustStatement,
        fetchAndImport: fetchAndImportTrustStatement,
        subscriptions: Object.freeze({
          list: listTrustSubscriptions,
          create: createTrustSubscription,
          get: getTrustSubscription,
          refresh: refreshTrustSubscription,
          pause: pauseTrustSubscription,
          resume: resumeTrustSubscription,
          remove: removeTrustSubscription,
        }),
      }),
    }),
    dom: Object.freeze({
      sanitizeFragment,
      sameOrigin,
    }),
  });
})(window);
