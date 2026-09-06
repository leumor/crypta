"""Implementation segment for the social trust portion of ``app_platform_smoke.py``."""

from __future__ import annotations

def social_inbox_spec(settings: Settings) -> dict[str, Any] | None:
    return next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "social-inbox"
        ),
        None,
    )

def collect_social_message_signing_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    vault_router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiVaultRouter.java"
    )
    vault_handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/AppVaultApiHandler.java"
    )
    request_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/SocialMessageRequest.java"
    )
    builder_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/SignedSocialMessageDocumentBuilder.java"
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    tests_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "platform-api/src/test/java/network/crypta/platform/api/appvault/SocialMessageRequestTest.java",
            "platform-api/src/test/java/network/crypta/platform/api/appvault/SignedSocialMessageDocumentBuilderTest.java",
            "platform-api/src/test/java/network/crypta/platform/api/AppVaultApiRouterTest.java",
            "platform-sdk-js/src/test/java/network/crypta/platform/sdk/js/CryptaPlatformSdkResourceTest.java",
        )
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/social-inbox-reference-app.md",
            "docs/app-secret-and-identity-vault.md",
            "docs/platform-api-contract.md",
            "docs/release-certification.md",
        )
    )
    checks = {
        "routeInContract": "/app-vault/identities/{identityId}/social-message" in contract_text,
        "contractVersionV11": "CURRENT_CONTRACT_VERSION = 24" in contract_text
        and "SOCIAL_MESSAGE_CONTRACT_VERSION = 11" in contract_text,
        "capabilitiesInContract": all(
            fragment in contract_text
            for fragment in (
                "PlatformApiCapabilities.VAULT_IDENTITIES_READ",
                "PlatformApiCapabilities.VAULT_IDENTITIES_USE",
            )
        ),
        "routerDispatchesBoundedRoute": "social-message" in vault_router_text,
        "handlerUsesFixedDomainAppVaultSigning": (
            "SocialMessageRequest.fromQuery" in vault_handler_text
            and "SocialMessageRequest.SIGNING_PURPOSE" in vault_handler_text
            and "signDomainSeparatedPayload" in vault_handler_text
        ),
        "requestRejectsGenericSigningInputs": (
            "ALLOWED_PARAMETERS" in request_text
            and "purpose" in tests_text
            and "payloadBase64" in tests_text
            and "crypta.social.message.v1" in request_text
        ),
        "builderReturnsPublicDocumentOnly": (
            "publicKeyBase64" in builder_text
            and "signatureBase64" in builder_text
            and "domainSeparatedPayload" in tests_text
            and "privateKey" in tests_text
        ),
        "sdkHelperUsesBoundedRoute": (
            "createSocialMessageDocument" in sdk_text
            and "/social-message" in sdk_text
            and "normalizeSocialMessageDocument" in sdk_text
        ),
        "docsDescribeBoundedSigningBoundary": (
            "crypta.social.message.v1" in docs_text
            and "not a generic browser signing API" in docs_text
            and "private key material" in docs_text
        ),
    }
    details = {
        "checks": checks,
        "route": "app-vault/identities/{identityId}/social-message",
        "domain": "crypta.social.message.v1",
        "contractVersion": 11,
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.social-message-signing",
            root_consequence(settings, "fail"),
            True,
            "Social message signing evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.social-message-signing",
        "pass",
        True,
        "Social message signing evidence passed.",
        source,
        details,
    )

def collect_social_inbox_reference_app_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {
        "appId": "social-inbox",
        "checks": {},
        "expectedPermissions": sorted(SOCIAL_INBOX_PERMISSIONS),
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox first-party app spec is missing.",
            source,
            details,
        )

    workspace = settings.workspace_root
    app_dir = workspace / "apps/social-inbox"
    source_static_dir = spec["sourceDir"] / "static"
    staged_static_dir = spec["stagedDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    app_readme = read_source(app_dir / "README.md")
    reference_doc = read_source(workspace / "docs/social-inbox-reference-app.md")
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    details.update(
        {
            "sourceDir": display_path(spec["sourceDir"], workspace),
            "stagedDir": display_path(spec["stagedDir"], workspace),
        }
    )
    disclosure = permission_disclosure_block(source_index)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    checks = details["checks"]
    checks["moduleExists"] = app_dir.is_dir()
    checks["stagedManifestPresent"] = manifest_path.is_file()
    checks["sourceStaticUiPresent"] = (source_static_dir / "index.html").is_file() and (
        source_static_dir / "app.js"
    ).is_file()
    checks["stagedSdkPresent"] = (staged_static_dir / "crypta-platform.js").is_file()
    checks["stagedDesignSystemPresent"] = all(
        (staged_static_dir / "crypta-ui" / asset_name).is_file()
        for asset_name in design_system_asset_names()
    )
    checks["usesSdkBootstrap"] = "CryptaPlatform.bootstrap.load({ appId })" in source_app_js
    checks["usesAppVaultIdentityFlow"] = all(
        fragment in source_app_js
        for fragment in (
            "CryptaPlatform.vault.identities.list",
            "CryptaPlatform.vault.identities.create",
            "CryptaPlatform.vault.identities.createSocialMessageDocument",
        )
    )
    checks["usesProfileMetadataFlow"] = "createProfileDocument" in source_app_js
    checks["usesGeneratedOutboxInsert"] = (
        "CryptaPlatform.content.insertAppDocument" in source_app_js
        and "application/vnd.crypta.social.outbox+json" in source_app_js
        and "social-outbox.json" in source_app_js
    )
    checks["usesSubscriptionAndFetchFlow"] = all(
        fragment in source_app_js
        for fragment in (
            "CryptaPlatform.content.subscriptions.create",
            "CryptaPlatform.content.subscriptions.refresh",
            "CryptaPlatform.content.subscriptions.pause",
            "CryptaPlatform.content.subscriptions.resume",
            "CryptaPlatform.content.subscriptions.remove",
            "CryptaPlatform.content.fetchText",
            "lastSeenResolvedUri",
        )
    )
    checks["usesDurableAppData"] = all(
        fragment in source_app_js
        for fragment in (
            "CryptaPlatform.data.records.getJson",
            "CryptaPlatform.data.records.putJson",
            "ui-state\", \"social-inbox\"",
            "social\", \"sources\"",
            "social\", \"outbox-summary\"",
            "social\", \"imported-message-index\"",
            "social\", \"read-state\"",
            "social\", \"drafts\"",
        )
    )
    checks["usesTrustAnnotations"] = (
        "CryptaPlatform.services.invoke" in source_app_js
        and "CryptaPlatform.services.bundles.request" in source_app_js
        and "trustScoreProviderAppId = \"trust-graph\"" in source_app_js
        and "trustScoreServiceId = \"trust.score\"" in source_app_js
        and "trustScoreContext = \"message-author\"" in source_app_js
        and "subjectKind: \"identity\"" in source_app_js
        and "CryptaPlatform.trust.score" not in source_app_js
    )
    checks["usesQueueSummary"] = "CryptaPlatform.queue.snapshot" in source_app_js
    checks["permissionDisclosureMentionsDeclaredPermissions"] = manifest_permissions.issubset(
        mentioned_permissions
    )
    checks["previewAndNonGoalCopyPresent"] = all(
        fragment in source_index + "\n" + app_readme + "\n" + reference_doc
        for fragment in (
            "social/mail-like",
            "migration",
            "not full WoT",
            "Freetalk",
            "Sone",
            "Freemail",
            "encrypted mail",
            "daemon-core message store",
            "network protocol",
        )
    )
    checks["noRawAdminOrBrowserStorage"] = all(
        forbidden not in source_app_js
        for forbidden in (
            "/api/v1/",
            "localStorage",
            "sessionStorage",
            "indexedDB",
            "document.cookie",
            "innerHTML",
            "insertAdjacentHTML",
            "CRYPTAD_APP_TOKEN",
        )
    )
    if manifest:
        details["manifest"] = {
            "appId": manifest.get("app.id"),
            "name": manifest.get("app.name"),
            "uiMode": manifest.get("app.ui.mode"),
            "uiEntry": manifest.get("app.ui.entry"),
            "permissions": sorted(manifest_permissions),
            "apiMinimumVersion": manifest.get("api.minimumVersion"),
            "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
            "experimentalCapabilitiesAccepted": manifest.get(
                "api.experimentalCapabilitiesAccepted"
            ),
            "serviceRequests": manifest.get("app.services.requests"),
            "trustScoreRequest": manifest.get("app.service-request.trust-score.service"),
        }
        checks["manifestDeclaresSocialInbox"] = (
            manifest.get("app.id") == "social-inbox"
            and manifest.get("app.name") in SOCIAL_INBOX_DISPLAY_NAMES
            and manifest.get("app.ui.mode") == "static"
            and manifest.get("app.ui.entry") == "static/index.html"
        )
        checks["manifestDeclaresSocialPermissions"] = SOCIAL_INBOX_PERMISSIONS.issubset(
            manifest_permissions
        )
        checks["manifestUsesContractV16"] = (
            manifest.get("api.minimumVersion") == "16"
            and manifest.get("api.maximumTestedVersion")
            == str(FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION)
            and manifest.get("api.experimentalCapabilitiesAccepted") == "true"
        )
        checks["manifestDeclaresTrustScoreServiceRequest"] = (
            manifest.get("app.services.requests") == "trust-score"
            and manifest.get("app.service-request.trust-score.provider") == "trust-graph"
            and manifest.get("app.service-request.trust-score.service") == "trust.score"
            and manifest.get("app.service-request.trust-score.scopes") == "score.read"
            and manifest.get("app.service-request.trust-score.contexts") == "message-author"
        )
    else:
        checks["manifestDeclaresSocialInbox"] = False
        checks["manifestDeclaresSocialPermissions"] = False
        checks["manifestUsesContractV16"] = False
        checks["manifestDeclaresTrustScoreServiceRequest"] = False

    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox reference app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox",
        "pass",
        True,
        "Social Inbox reference app evidence passed.",
        source,
        details,
    )

def collect_social_inbox_signed_message_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {"appId": "social-inbox", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox-signed-message",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox signed-message evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    reference_doc = read_source(workspace / "docs/social-inbox-reference-app.md")
    request_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/SocialMessageRequest.java"
    )
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestAllowsBoundedSigning"] = (
        {"vault.identities.read", "vault.identities.use"}.issubset(permissions)
        and manifest.get("api.minimumVersion") in {"11", "12", "16"}
    )
    checks["usesSdkBoundedSigner"] = (
        "CryptaPlatform.vault.identities.createSocialMessageDocument" in app_js
        and "ensureSignedSocialMessage" in app_js
        and "signature.domain !== socialMessageType" in app_js
    )
    checks["verifiesImportedMessageSignatures"] = (
        "verifySocialMessageSignature" in app_js
        and "canonicalSocialMessagePayload" in app_js
        and "expectedSocialMessageId" in app_js
        and "canonicalSocialMessageIdPayload" in app_js
        and "messageIdPattern" in app_js
        and "Social message id does not match canonical payload." in app_js
        and "window.crypto.subtle.verify" in app_js
        and "signature.publicKeyFingerprint !== message.authorFingerprint" in app_js
        and "const publicKeyBytes = decodeBase64(signature.publicKeyBase64" in app_js
        and "const publicKeyFingerprint = await sha256Hex(publicKeyBytes)" in app_js
        and "publicKeyFingerprint !== stringValue(signature.publicKeyFingerprint)" in app_js
    )
    checks["documentShapeIsBounded"] = all(
        fragment in request_text
        for fragment in (
            "MAX_BODY_LENGTH = 4096",
            "MAX_SUBJECT_LENGTH = 160",
            "MAX_TAG_COUNT = 12",
            "MAX_SIGNED_PAYLOAD_BYTES",
            "FORMAT_TEXT_PLAIN",
        )
    ) and "requireIsoTimestamp" in app_js
    checks["docsDescribeSignedMessageFormat"] = (
        "Signed social message document" in reference_doc
        and "crypta.social.message.v1" in reference_doc
        and "domain-separated" in reference_doc
    )
    details["redaction"] = {
        "privateIdentityMaterialExcluded": True,
        "genericSigningInputsExcluded": True,
        "rawSignatureValuesExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox signed-message check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox-signed-message",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox signed-message evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox-signed-message",
        "pass",
        True,
        "Social Inbox signed-message evidence passed.",
        source,
        details,
    )

def collect_social_inbox_subscriptions_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {"appId": "social-inbox", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox-subscriptions",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox subscription evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    reference_doc = read_source(workspace / "docs/social-inbox-reference-app.md")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestDeclaresSubscriptionPermissions"] = {
        "content.fetch",
        "content.subscribe",
    }.issubset(permissions)
    checks["uiDisclosesSubscriptionWorkflow"] = (
        "content.subscribe" in permission_disclosure_block(index)
        and "USK social sources" in index
        and "Sources and subscriptions" in index
    )
    checks["appUsesPlatformSubscriptionLifecycle"] = all(
        fragment in app_js
        for fragment in (
            "CryptaPlatform.content.subscriptions.create",
            "CryptaPlatform.content.subscriptions.list",
            "CryptaPlatform.content.subscriptions.refresh",
            "CryptaPlatform.content.subscriptions.pause",
            "CryptaPlatform.content.subscriptions.resume",
            "CryptaPlatform.content.subscriptions.remove",
            "isSocialSourceUri",
            "lastSeenResolvedUri",
            "updateCount",
            "lastError",
        )
    )
    checks["manualFetchUsesBoundedContentFetch"] = (
        "CryptaPlatform.content.fetchText" in app_js
        and "maxFetchedDocumentBytes" in app_js
        and "parseJsonObject" in app_js
    )
    checks["docsDescribeDurableUskSources"] = (
        "content.subscribe" in reference_doc
        and "durable" in reference_doc.lower()
        and "USK" in reference_doc
        and "raw fetched content" in reference_doc
    )
    details["redaction"] = {
        "rawFetchedContentExcluded": True,
        "sourceMetadataOnly": True,
        "absolutePathsExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox subscription check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox-subscriptions",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox subscription evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox-subscriptions",
        "pass",
        True,
        "Social Inbox subscription evidence passed.",
        source,
        details,
    )

def collect_social_inbox_app_data_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {"appId": "social-inbox", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox-app-data",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox app-data evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "apps/social-inbox/README.md",
            "docs/social-inbox-reference-app.md",
            "docs/app-data-store.md",
            "docs/release-certification.md",
        )
    )
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestDeclaresAppDataPermissions"] = {
        "app.data.read",
        "app.data.write",
    }.issubset(permissions)
    checks["usesSdkJsonRecordHelpers"] = (
        "CryptaPlatform.data.records.getJson" in app_js
        and "CryptaPlatform.data.records.putJson" in app_js
    )
    checks["persistsNamedBoundedRecords"] = all(
        fragment in app_js
        for fragment in (
            "ui-state\", \"social-inbox\"",
            "social\", \"sources\"",
            "social\", \"outbox-summary\"",
            "social\", \"imported-message-index\"",
            "social\", \"read-state\"",
            "social\", \"drafts\"",
            "maxSources",
            "maxImportedMessages",
            "maxReadStateEntries",
            "boundedDrafts",
            "boundedReadState",
            "Object.create(null)",
            "isSafeMessageId",
        )
    )
    checks["signingDoesNotOverwritePublishSummary"] = (
        "persistOutboxSummary(await localOutboxSummary())" not in app_js
        and "await persistOutboxSummary(summary)" in app_js
    )
    checks["storesSafeSummariesOnly"] = all(
        fragment in app_js
        for fragment in (
            "bodySha256",
            "bodyPreview",
            "signatureSha256",
            "insertUriRedaction",
            "redactedInsertUri",
            "uriHash",
            "uriSummary",
            "publicSourceUriHash",
            "publicSourceUriSummary",
        )
    ) and "privateInsertUri" not in app_js and not re.search(r"\bsource\.uri\b", app_js)
    checks["permissionDisclosureMentionsAppData"] = (
        "app.data.read" in permission_disclosure_block(index)
        and "app.data.write" in permission_disclosure_block(index)
    )
    checks["docsDescribePrivacyRules"] = (
        "reference-app.social-inbox-app-data" in docs_text
        and "private insert URIs" in docs_text
        and "raw source URIs" in docs_text
        and "browser-session tokens" in docs_text
        and "raw fetched documents" in docs_text
    )
    checks["noBrowserStorageOrRawAdminPath"] = (
        "/api/v1/" not in app_js
        and "localStorage" not in app_js
        and "sessionStorage" not in app_js
        and "document.cookie" not in app_js
    )
    details["redaction"] = {
        "rawMessageBodiesExcludedFromEvidence": True,
        "rawFetchedDocumentsExcluded": True,
        "privateInsertUrisExcluded": True,
        "tokensExcluded": True,
        "localPathsExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox app-data check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox-app-data",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox app-data evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox-app-data",
        "pass",
        True,
        "Social Inbox app-data evidence passed.",
        source,
        details,
    )

def collect_social_inbox_trust_annotation_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {"appId": "social-inbox", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox-trust-annotations",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox trust annotation evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    reference_doc = read_source(workspace / "docs/social-inbox-reference-app.md")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestDeclaresAppServiceCapabilities"] = (
        {"app.services.read", "app.services.call"}.issubset(permissions)
        and "trust.read" not in permissions
    )
    checks["manifestDeclaresTrustScoreRequest"] = (
        manifest.get("app.service-request.trust-score.provider") == "trust-graph"
        and manifest.get("app.service-request.trust-score.service") == "trust.score"
        and manifest.get("app.service-request.trust-score.scopes") == "score.read"
        and manifest.get("app.service-request.trust-score.contexts") == "message-author"
    )
    checks["appQueriesAuthorScores"] = (
        "CryptaPlatform.services.invoke" in app_js
        and "CryptaPlatform.services.grants.list" in app_js
        and "CryptaPlatform.services.bundles.request" in app_js
        and "subjectKind: \"identity\"" in app_js
        and "trustScoreContext = \"message-author\"" in app_js
        and "authorFingerprint" in app_js
        and "CryptaPlatform.trust.score" not in app_js
    )
    checks["uiShowsNeutralAndScoredStates"] = (
        "Trust score unavailable / grant required" in app_js
        and "Trust score unavailable / grant revoked" in app_js
        and "evidenceCount" in app_js
        and "Request trust grant" in index
        and "Refresh trust" in index
    )
    checks["unknownScoresRemainUnscored"] = (
        "optionalNumberField" in app_js
        and "contributingEvidenceCount" in app_js
        and "[\"trusted\", \"distrusted\", \"mixed\"].includes(trustStatus)" in app_js
        and "return { status: \"unscored\", summary: \"No local trust evidence.\" }" in app_js
    )
    checks["docsFrameScoresAsAnnotations"] = (
        ("Trust Graph Preview" in reference_doc or "Trust Graph Local RC" in reference_doc)
        and "message-author" in reference_doc
        and "Trust Score Service grant" in reference_doc
        and "not a moderation decision" in reference_doc
    )
    details["redaction"] = {
        "trustEvidenceSummariesOnly": True,
        "messageBodiesExcludedFromEvidence": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox trust annotation check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox-trust-annotations",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox trust annotation evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox-trust-annotations",
        "pass",
        True,
        "Social Inbox trust annotation evidence passed.",
        source,
        details,
    )

def collect_social_inbox_rc_threading_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = social_inbox_spec(settings)
    details: dict[str, Any] = {
        "appId": "social-inbox",
        "checks": {},
        "sourceFiles": [
            "apps/social-inbox/src/staged/static/app.js",
            "apps/social-inbox/src/staged/static/index.html",
            "apps/social-inbox/src/staged/cryptad-app.properties.template",
            "docs/social-inbox-reference-app.md",
            "apps/social-inbox/README.md",
        ],
        "redaction": {
            "rawMessageBodiesExcluded": True,
            "rawFetchedContentExcluded": True,
            "rawSignaturesExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "privateKeysExcluded": True,
            "absolutePathsExcluded": True,
        },
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.social-inbox-rc-threading",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox RC threading evidence is missing its first-party app spec.",
            source,
            details,
        )

    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "apps/social-inbox/README.md",
            "docs/social-inbox-reference-app.md",
            "tools/release-certification/README.md",
        )
    )
    docs_lower = normalized_source_text(docs_text)
    source_manifest_path = spec["sourceDir"] / "cryptad-app.properties.template"
    staged_manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_manifest = parse_properties(source_manifest_path) if source_manifest_path.is_file() else {}
    staged_manifest = parse_properties(staged_manifest_path) if staged_manifest_path.is_file() else {}
    manifest = staged_manifest or source_manifest
    migration_names = parse_permission_set(manifest.get("app.data.migrations", ""))
    checks = details["checks"]
    checks["threadBuildingLogic"] = all(
        fragment in app_js
        for fragment in (
            "buildThreadIndex",
            "normalizeReplyReference",
            "messageThreadRootId",
            "threadSortKey",
            "messageSortKey",
            "threadUnreadCount",
            "threadContainsMessage",
            "replyTo",
        )
    ) and any(fragment in app_js.lower() for fragment in ("cycle", "visited", "visiting"))
    checks["threadRenderingIsBoundedAndDomSafe"] = (
        all(
            fragment in app_js
            for fragment in (
                "maxThreadDepth",
                "maxRenderedThreadMessages",
                "textContent",
                "replaceChildren",
            )
        )
        and "innerHTML" not in app_js
        and "insertAdjacentHTML" not in app_js
    )
    checks["replyActionUsesExistingReplyTo"] = (
        "Reply" in app_js + index
        and "replyTo" in app_js
        and "createSocialMessageDocument" in app_js
        and "reply-message" not in app_js
    )
    checks["channelFilteringIsLocal"] = (
        "All channels" in app_js + index
        and all(
            fragment in app_js
            for fragment in (
                "channelFilter",
                "selectedChannel",
                "maxImportedChannelLength",
                "general",
            )
        )
    )
    checks["boundedLocalSearch"] = all(
        fragment in app_js
        for fragment in (
            "maxSearchQueryLength",
            "threadContainsMessage",
            "searchQuery",
            "bodyPreview",
            "sourceLabel",
        )
    )
    checks["threadActionsPersistSafeState"] = (
        all(
            fragment in app_js
            for fragment in (
                "markThreadRead",
                "markThreadUnread",
                "archiveThread",
                "toggleThreadPin",
                "isSafeMessageId",
                "boundedReadState",
            )
        )
        and "read-state" in app_js
    )
    checks["authorProfileDisplayIsSafe"] = all(
        fragment in app_js
        for fragment in (
            "authorLabel",
            "authorFingerprint",
            "profileUri",
            "optionalCryptaContentUri",
            "copyProfileUri",
        )
    )
    checks["dedupePreservesSafeSourceSummaries"] = all(
        fragment in app_js
        for fragment in (
            "seenCount",
            "firstImportedAt",
            "lastSeenAt",
            "sourcesSeen",
            "sourceSummariesForDedupe",
            "sourceUriHash",
        )
    )
    checks["subscriptionRefreshUxIsExplicit"] = all(
        fragment in app_js + index
        for fragment in (
            "refreshAllSources",
            "lastCheckedAt",
            "lastSeenEdition",
            "updateCount",
            "lastError",
        )
    )
    checks["trustGraphMediatedOnly"] = (
        all(
            fragment in app_js
            for fragment in (
                "CryptaPlatform.services.get",
                "CryptaPlatform.services.grants.list",
                "CryptaPlatform.services.bundles.request",
                "CryptaPlatform.services.invoke",
            )
        )
        and "CryptaPlatform.trust.score" not in app_js
        and "/api/v1/trust-graph/score" not in app_js
        and "/api/v1/" not in app_js
    )
    checks["noUnsafeBrowserPersistenceOrExecution"] = all(
        forbidden not in app_js
        for forbidden in (
            "localStorage",
            "sessionStorage",
            "indexedDB",
            "document.cookie",
            "eval(",
            "new Function",
        )
    )
    schema_manifest_text = "\n".join(f"{key}={value}" for key, value in manifest.items())
    migration_script_present = any(
        (spec[manifest_dir] / "bin/migrate-social-inbox-data.sh").is_file()
        for manifest_dir in ("sourceDir", "stagedDir")
    )
    checks["manifestUsesAdditiveBetaSchemaContract"] = (
        manifest.get("app.data.schema.current") == "1"
        and manifest.get("app.data.schema.namespaces") == "ui-state,social"
        and manifest.get("app.data.schema.namespace.ui-state.current") == "1"
        and manifest.get("app.data.schema.namespace.social.current") == "1"
        and migration_names == set()
        and "app.data.migration.social-v1-v2" not in schema_manifest_text
        and not migration_script_present
    )
    checks["appWritesExistingSchemaVersion"] = (
        "const dataSchemaVersion = 1" in app_js
        and "namespaceSchemaVersions" in app_js
        and '"ui-state": 1' in app_js
        and "social: dataSchemaVersion" in app_js
        and "schemaVersion: schemaVersionForRecord(record)" in app_js
    )
    checks["docsFrameRcReferenceAndNonGoals"] = (
        ("social inbox rc" in docs_lower or "social inbox reference" in docs_lower)
        and "thread" in docs_lower
        and "read state" in docs_lower
        and "trust graph" in docs_lower
        and "annotations only" in docs_lower
        and "encrypted mail" in docs_lower
        and "freetalk" in docs_lower
        and "sone" in docs_lower
        and "freemail" in docs_lower
        and ("full wot" in docs_lower or "full web of trust" in docs_lower)
        and ("daemon-core message" in docs_lower or "outside daemon core" in docs_lower)
    )
    checks["evidenceIdDocumented"] = "reference-app.social-inbox-rc-threading" in docs_text
    details["manifest"] = {
        "appId": manifest.get("app.id"),
        "name": manifest.get("app.name"),
        "schemaVersion": manifest.get("app.data.schema.current"),
        "namespaces": manifest.get("app.data.schema.namespaces"),
        "migrations": sorted(migration_names),
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"social inbox RC threading check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.social-inbox-rc-threading",
            root_consequence(settings, "fail"),
            True,
            "Social Inbox RC threading evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.social-inbox-rc-threading",
        "pass",
        True,
        "Social Inbox RC threading evidence passed.",
        source,
        details,
    )

def collect_trust_social_beta_hardening_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    trust_spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "trust-graph"
        ),
        None,
    )
    social_spec = social_inbox_spec(settings)
    details: dict[str, Any] = {
        "checks": {},
        "sourceFiles": [
            "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustGraphImportPreview.java",
            "platform-api/src/main/java/network/crypta/platform/api/PlatformApiTrustGraphRoutes.java",
            "platform-api/src/main/java/network/crypta/platform/api/trust/TrustGraphApiHandler.java",
            "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js",
            "apps/trust-graph/src/staged/static/app.js",
            "apps/social-inbox/src/staged/static/app.js",
            "docs/trust-graph-preview.md",
            "docs/social-inbox-reference-app.md",
            "docs/app-service-discovery-and-grants.md",
            "docs/user-consent-and-permission-upgrade-ux.md",
        ],
        "redaction": {
            "rawTrustStatementsExcluded": True,
            "rawFetchedContentExcluded": True,
            "rawMessageBodiesExcluded": True,
            "rawAppDataExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "absolutePathsExcluded": True,
        },
    }
    if trust_spec is None or social_spec is None:
        return EvidenceItem(
            "app-platform.trust-social-beta-hardening",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph and Social Inbox beta hardening evidence is missing first-party app specs.",
            source,
            details,
        )

    api_contract = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    api_routes = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiTrustGraphRoutes.java"
    )
    api_handler = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/trust/TrustGraphApiHandler.java"
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    preview_model = read_source(
        workspace
        / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustGraphImportPreview.java"
    )
    scorer_text = read_source(
        workspace
        / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustGraphScorer.java"
    )
    trust_app_js = read_source(trust_spec["sourceDir"] / "static/app.js")
    trust_index = read_source(trust_spec["sourceDir"] / "static/index.html")
    social_app_js = read_source(social_spec["sourceDir"] / "static/app.js")
    social_index = read_source(social_spec["sourceDir"] / "static/index.html")
    social_manifest_path = social_spec["sourceDir"] / "cryptad-app.properties.template"
    social_manifest = (
        parse_properties(social_manifest_path) if social_manifest_path.is_file() else {}
    )
    router_test_text = read_source(
        workspace / "platform-api/src/test/java/network/crypta/platform/api/TrustGraphApiRouterTest.java"
    )
    social_test_text = read_source(
        workspace
        / "apps/social-inbox/src/test/java/network/crypta/apps/socialinbox/SocialInboxBundleStagingTest.java"
    )
    trust_test_text = read_source(
        workspace
        / "apps/trust-graph/src/test/java/network/crypta/apps/trustgraph/TrustGraphBundleStagingTest.java"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-graph-preview.md",
            "docs/social-inbox-reference-app.md",
            "docs/app-service-discovery-and-grants.md",
            "docs/user-consent-and-permission-upgrade-ux.md",
            "docs/release-certification.md",
            "tools/release-certification/README.md",
        )
    )
    docs_lower = normalized_source_text(docs_text)
    social_manifest_migrations = parse_permission_set(social_manifest.get("app.data.migrations", ""))
    checks = details["checks"]
    checks["trustGraphLocalScopeWarning"] = all(
        fragment in normalized_source_text(trust_index + "\n" + docs_text)
        for fragment in (
            "trust graph local rc",
            "local operator",
            "not global truth",
            "no legacy wot",
            "freetalk",
            "sone",
            "freemail",
        )
    )
    checks["trustGraphImportPreviewRouteSdkAndUi"] = all(
        fragment in api_contract + api_routes + api_handler + sdk_text + trust_app_js
        for fragment in (
            "/trust-graph/import-preview",
            "/trust-graph/import-preview-uri",
            "previewTrustImport",
            "previewImport",
            "commitPendingImport",
            "clearPendingImport",
            "expectedDocumentFingerprint",
            "rawContentDiscarded",
            "candidateStatementCount",
        )
    )
    checks["trustGraphDuplicateIssuerAndConflicts"] = all(
        fragment in preview_model + trust_app_js + router_test_text
        for fragment in (
            "duplicateIssuerCount",
            "conflictCount",
            "issuerSubjectKey",
            "duplicateIssuer",
            "conflictStatus",
            "route_whenWriterPreviewsDuplicateIssuerImport_expectRedactedConflictSummary",
        )
    )
    checks["trustGraphSourceBudgetAndManualReview"] = (
        "AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT" in api_handler
        and (
            "trust_graph_import_budget" in api_handler
            or (
                "reserveTrustGraphImportBudget" in api_handler
                and "acquireTrustGraphImportBudgetLease" in api_handler
            )
        )
        and "Manual review recommended" in preview_model
        and "maxBytes" in preview_model
        and "MAX_PREVIEW_STATEMENTS" in preview_model
    )
    checks["trustGraphBoundedScoreAndLifecycle"] = all(
        fragment in api_handler + scorer_text + trust_app_js + sdk_text + trust_test_text
        for fragment in (
            "anchorLifecycle",
            "deprecateAnchor",
            "revokeAnchor",
            "reactivateAnchor",
            "MAX_EVIDENCE_ROWS",
            "evidenceTruncated",
            "nonContributingReasons",
        )
    )
    checks["trustGraphRecoveryAndAuditSummaries"] = (
        "audit" in trust_app_js
        and (
            "CryptaPlatform.data.export" in sdk_text
            or ("export: exportAppData" in sdk_text and "import: importAppData" in sdk_text)
        )
        and "backup" in docs_lower
        and "export" in docs_lower
        and "import preview" in docs_lower
        and "path-free" in docs_lower
    )
    checks["socialInboxMultiSourceControls"] = all(
        fragment in social_app_js + social_index
        for fragment in (
            "maxSources",
            "CryptaPlatform.content.subscriptions.create",
            "Pause source",
            "Resume source",
            "Block source",
            "Unblock source",
            "subscriptionStatusSummary",
        )
    )
    checks["socialInboxThreadReadAndProfileState"] = all(
        fragment in social_app_js
        for fragment in (
            "buildThreadIndex",
            "replyTo",
            "markThreadRead",
            "markThreadUnread",
            "read-state",
            "authorLabel",
            "profileUri",
            "copyProfileUri",
        )
    )
    checks["socialInboxLocalMuteBlockAndExport"] = all(
        fragment in social_app_js + social_index + social_test_text
        for fragment in (
            "localFilters",
            "mutedAuthors",
            "blockedSources",
            "Mute author",
            "Export visible",
            "boundedExportSummary",
            "maxExportedMessages",
            "export-summary",
        )
    )
    checks["socialInboxTrustAnnotationsUseGrantPath"] = (
        all(
            fragment in social_app_js
            for fragment in (
                "CryptaPlatform.services.get",
                "CryptaPlatform.services.grants.list",
                "CryptaPlatform.services.bundles.request",
                "CryptaPlatform.services.invoke",
                "revalidation-required",
                "grant revoked",
            )
        )
        and "CryptaPlatform.trust.score" not in social_app_js
        and "/api/v1/trust-graph/score" not in social_app_js
    )
    checks["socialInboxAdditiveSchemaReadiness"] = (
        social_manifest.get("app.data.schema.current") == "1"
        and social_manifest.get("app.data.schema.namespace.ui-state.current") == "1"
        and social_manifest.get("app.data.schema.namespace.social.current") == "1"
        and social_manifest_migrations == set()
        and "app.data.migration.social-v1-v2" not in "\n".join(
            f"{key}={value}" for key, value in social_manifest.items()
        )
        and not (social_spec["sourceDir"] / "bin/migrate-social-inbox-data.sh").is_file()
        and "local-filters" in social_app_js
        and "schemaVersionForRecord" in social_app_js
    )
    checks["consentAndGrantMarkers"] = all(
        fragment in docs_lower
        for fragment in (
            "snapshot digest",
            "stale approval",
            "backup-before-update",
            "service-grant",
            "revalidation",
            "trust graph import preview",
            "social inbox",
        )
    )
    redaction_search_text = normalized_source_text(
        docs_text + " " + preview_model + " " + social_app_js
    )
    checks["redactionAndSupportBundleMarkers"] = all(
        fragment in redaction_search_text
        for fragment in (
            "raw fetched content",
            "private insert uri",
            "browser session token",
            "absolute local paths",
            "raw app data",
            "raw signatures",
            "rawcontentdiscarded",
        )
    )
    checks["evidenceIdDocumented"] = "app-platform.trust-social-beta-hardening" in docs_text

    errors = [
        f"trust/social beta hardening check failed: {name}"
        for name, passed in checks.items()
        if passed is not True
    ]
    details["manifest"] = {
        "socialInboxSchema": social_manifest.get("app.data.schema.current"),
        "socialInboxMigrations": sorted(social_manifest_migrations),
    }
    if errors:
        return EvidenceItem(
            "app-platform.trust-social-beta-hardening",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph and Social Inbox beta hardening evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-social-beta-hardening",
        "pass",
        True,
        "Trust Graph and Social Inbox beta hardening evidence passed.",
        source,
        details,
    )

def collect_trust_social_content_format_profiles_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    details: dict[str, Any] = {
        "checks": {},
        "sourceFiles": [
            "platform-api/src/main/java/network/crypta/platform/api/contentformats/ContentFormatProfileRegistry.java",
            "platform-api/src/main/java/network/crypta/platform/api/contentformats/ContentFormatProfile.java",
            "platform-api/src/main/java/network/crypta/platform/api/contentformats/ContentFormatVersionPolicy.java",
            "platform-api/src/main/java/network/crypta/platform/api/appvault/ProfileDocumentRequest.java",
            "platform-api/src/main/java/network/crypta/platform/api/appvault/SocialMessageRequest.java",
            "platform-api/src/main/java/network/crypta/platform/api/appvault/TrustStatementRequest.java",
            "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustDocumentTypes.java",
            "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js",
            "apps/profile-publisher/src/staged/static/app.js",
            "apps/feed-reader/src/staged/static/app.js",
            "apps/trust-graph/src/staged/static/app.js",
            "apps/social-inbox/src/staged/static/app.js",
            "docs/trust-social-content-format-profiles.md",
        ],
        "redaction": {
            "rawProfileDocumentsExcluded": True,
            "rawMessageBodiesExcluded": True,
            "rawTrustStatementsExcluded": True,
            "rawFetchedContentExcluded": True,
            "rawSignaturesExcluded": True,
            "rawAppDataExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "absolutePathsExcluded": True,
        },
    }
    registry = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/contentformats/ContentFormatProfileRegistry.java"
    )
    version_policy = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/contentformats/ContentFormatVersionPolicy.java"
    )
    profile_request = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/ProfileDocumentRequest.java"
    )
    social_request = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/SocialMessageRequest.java"
    )
    trust_request = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/TrustStatementRequest.java"
    )
    queue_handler = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/queue/QueueApiHandler.java"
    )
    content_policy = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/ContentFetchPolicy.java"
    )
    trust_types = read_source(
        workspace
        / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustDocumentTypes.java"
    )
    trust_canonicalizer = read_source(
        workspace
        / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph/TrustStatementCanonicalizer.java"
    )
    sdk = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    app_sources = {
        "profile-publisher": read_source(
            workspace / "apps/profile-publisher/src/staged/static/app.js"
        ),
        "feed-reader": read_source(workspace / "apps/feed-reader/src/staged/static/app.js"),
        "trust-graph": read_source(workspace / "apps/trust-graph/src/staged/static/app.js"),
        "social-inbox": read_source(workspace / "apps/social-inbox/src/staged/static/app.js"),
    }
    app_indexes = {
        "profile-publisher": read_source(
            workspace / "apps/profile-publisher/src/staged/static/index.html"
        ),
        "feed-reader": read_source(workspace / "apps/feed-reader/src/staged/static/index.html"),
        "trust-graph": read_source(workspace / "apps/trust-graph/src/staged/static/index.html"),
        "social-inbox": read_source(workspace / "apps/social-inbox/src/staged/static/index.html"),
    }
    test_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "platform-api/src/test/java/network/crypta/platform/api/contentformats/ContentFormatProfileRegistryTest.java",
            "platform-api/src/test/java/network/crypta/platform/api/appvault/ProfileDocumentRequestTest.java",
            "platform-api/src/test/java/network/crypta/platform/api/appvault/SocialMessageRequestTest.java",
            "platform-api/src/test/java/network/crypta/platform/api/appvault/SignedProfileDocumentBuilderTest.java",
            "platform-api/src/test/java/network/crypta/platform/api/appvault/SignedSocialMessageDocumentBuilderTest.java",
            "platform-trustgraph/src/test/java/network/crypta/platform/trustgraph/TrustStatementCanonicalizerTest.java",
            "platform-trustgraph/src/test/java/network/crypta/platform/trustgraph/TrustStatementParserTest.java",
            "platform-trustgraph/src/test/java/network/crypta/platform/trustgraph/TrustStatementVerifierTest.java",
            "platform-sdk-js/src/test/java/network/crypta/platform/sdk/js/CryptaPlatformSdkResourceTest.java",
            "apps/profile-publisher/src/test/java/network/crypta/apps/profilepublisher/ProfilePublisherBundleStagingTest.java",
            "apps/feed-reader/src/test/java/network/crypta/apps/feedreader/FeedReaderBundleStagingTest.java",
            "apps/trust-graph/src/test/java/network/crypta/apps/trustgraph/TrustGraphBundleStagingTest.java",
            "apps/social-inbox/src/test/java/network/crypta/apps/socialinbox/SocialInboxBundleStagingTest.java",
        )
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-social-content-format-profiles.md",
            "docs/feed-reader-reference-app.md",
            "docs/trust-graph-preview.md",
            "docs/social-inbox-reference-app.md",
            "docs/profile-publisher-reference-app.md",
            "docs/platform-api-compatibility-support-window.md",
            "docs/production-beta-release-pipeline.md",
            "docs/production-beta-go-no-go-dashboard.md",
            "docs/app-platform-beta-known-limitations.md",
            "docs/release-certification.md",
            "tools/release-certification/README.md",
        )
    )
    docs_lower = normalized_source_text(docs_text)
    policy_text = registry + "\n" + version_policy
    test_lower = normalized_source_text(test_text)
    checks = details["checks"]
    profile_ids = (
        "crypta.profile.v1",
        "crypta.feed.snapshot.v1",
        "crypta.trust.statement.v1",
        "crypta.social.message.v1",
        "crypta.social.outbox.v1",
    )
    checks["registryProfilesExist"] = (
        all(profile_id in registry for profile_id in profile_ids)
        and all(
            fragment in registry
            for fragment in (
                "ContentFormatProfile PROFILE_DOCUMENT",
                "ContentFormatProfile FEED_SNAPSHOT",
                "ContentFormatProfile TRUST_STATEMENT",
                "ContentFormatProfile SOCIAL_MESSAGE",
                "ContentFormatProfile SOCIAL_OUTBOX",
                "ContentFormatVersionPolicy.CONSERVATIVE_V1",
                "FETCHED_DOCUMENT_MAX_BYTES",
                "DEFAULT_SIGNED_PAYLOAD_MAX_BYTES",
            )
        )
        and "reject_unknown_fields" in policy_text
    )
    checks["javaRoutesUseRegistry"] = all(
        "ContentFormatProfileRegistry" in source_text
        for source_text in (
            profile_request,
            social_request,
            trust_request,
            queue_handler,
            content_policy,
        )
    )
    checks["trustgraphDriftIsTested"] = (
        "TrustDocumentTypes.TRUST_STATEMENT_V1" in test_text
        and "TrustDocumentTypes.TRUST_STATEMENT_CONTENT_TYPE" in test_text
        and "TrustStatementCanonicalizer.canonicalPayloadBytes" in test_text
        and "crypta.trust.statement.v1\\n" in test_text
        and "TrustDocumentTypes.TRUST_STATEMENT_V1" in trust_canonicalizer
        and "application/vnd.crypta.trust+json" in trust_types
    )
    checks["sdkMirrorAndHelpersUseProfiles"] = (
        all(
            fragment in sdk
            for fragment in (
                "const contentFormats = Object.freeze",
                "profileDocument: Object.freeze",
                "feedSnapshot: Object.freeze",
                "trustStatement: Object.freeze",
                "socialMessage: Object.freeze",
                "socialOutbox: Object.freeze",
                "application/vnd.crypta.profile+json",
                "application/vnd.crypta.feed+json",
                "application/vnd.crypta.trust+json",
                "application/vnd.crypta.social.outbox+json",
                "profile.publish.v1",
                "crypta.social.message.v1",
                "contentFormats.profileDocument.contentType",
                "contentFormats.feedSnapshot.contentType",
                "contentFormats.trustStatement.contentType",
                "contentFormats.feedSnapshot.maxDocumentBytes",
            )
        )
        and "contentFormats," in sdk
    )
    checks["referenceAppsUseSdkProfiles"] = all(
        "CryptaPlatform.contentFormats" in text for text in app_sources.values()
    ) and all("Format profile" in text for text in app_indexes.values())
    checks["validationCoversMalformedOversizedVersionDeprecatedAndSignature"] = (
        (
            "unknown field" in test_lower
            or "field unsupported is not supported" in test_lower
            or "query parameter 'purpose' is not supported" in test_lower
        )
        and "oversized_document" in test_text
        and "feed snapshot document is too large" in test_lower
        and "unsupported_version" in test_text
        and "deprecated_version" in test_text
        and "payloadchangesaftersigning" in test_lower
        and "signaturebase64" in test_lower
        and (
            'assertfalse(deprecatedresult.tostring().contains("signaturebase64"))'
            in compact_source_text(test_text).lower()
        )
    )
    checks["docsExistWithLegacyNonGoals"] = (
        "these content profiles are crypta app ecosystem profiles. they are not compatibility promises for legacy wot, freetalk, sone, freemail, or any old plugin abi/protocol."
        in docs_lower
        and all(term in docs_lower for term in ("wot", "freetalk", "sone", "freemail"))
        and all(term in docs_lower for term in ("malformed", "oversized", "unsupported", "deprecated"))
    )
    checks["releaseEvidenceDocumented"] = all(
        fragment in docs_text
        for fragment in (
            "app-platform.trust-social-content-format-profiles",
            "content-format risk",
            "raw signatures",
            "raw fetched content",
        )
    )
    checks["platformApiStableBaselineNotExpanded"] = (
        "content profiles are not Platform API 1.0 stable baseline route guarantees" in docs_text
        or "not Platform API 1.0 stable baseline route guarantees" in docs_text
    )
    details["profiles"] = list(profile_ids)
    details["evidenceLevel"] = "source-inspection"
    from .stable_content_profile_review import bound_summary

    try:
        review = bound_summary(workspace)
        details["executableReview"] = review or {"evidenceLevel": "not-observed"}
    except (ValueError, OSError, KeyError):
        checks["executableReviewBinding"] = False
        details["executableReview"] = {"evidenceLevel": "invalid-or-stale"}

    errors = [
        f"content format profile check failed: {name}"
        for name, passed in checks.items()
        if passed is not True
    ]
    if errors:
        return EvidenceItem(
            "app-platform.trust-social-content-format-profiles",
            root_consequence(settings, "fail"),
            True,
            "Trust/social content format profile evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-social-content-format-profiles",
        "pass",
        True,
        "Trust/social content format profile evidence passed.",
        source,
        details,
    )

def collect_social_mail_migration_preview_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    app_js = read_source(workspace / "apps/social-inbox/src/staged/static/app.js")
    index = read_source(workspace / "apps/social-inbox/src/staged/static/index.html")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/social-inbox-reference-app.md",
            "docs/app-platform-developer-portal.md",
            "docs/app-platform-beta-tutorials.md",
            "docs/app-platform-beta-known-limitations.md",
            "docs/app-permissions-and-audit.md",
            "docs/release-certification.md",
            "tools/release-certification/README.md",
        )
    )
    docs_lower = docs_text.lower()
    checks = {
        "migrationFramingPresent": (
            "social/mail-like" in docs_text
            and ("reference app" in docs_lower or "migration" in docs_lower)
            and ("outside the daemon" in docs_lower or "outside daemon core" in docs_lower)
        ),
        "nonGoalsDocumented": all(
            fragment in docs_text
            for fragment in (
                "old plugin ABI compatibility",
                "Freetalk",
                "Sone",
                "Freemail",
                "encrypted mail",
                "network protocol change",
                "daemon-core message protocol",
            )
        ),
        "appComposesExpectedPlatformSurfaces": all(
            fragment in app_js
            for fragment in (
                "createSocialMessageDocument",
                "insertAppDocument",
                "content.subscriptions",
                "data.records",
                "services.invoke",
            )
        ),
        "uiStatesPreviewBoundary": (
            "Reference app scope" in index
            and "not Freetalk, Sone, Freemail" in index
            and "does not add a daemon-core message store" in index
        ),
        "evidenceIdsDocumented": all(
            evidence_id in docs_text
            for evidence_id in (
                "reference-app.social-inbox",
                "reference-app.social-inbox-signed-message",
                "reference-app.social-inbox-subscriptions",
                "reference-app.social-inbox-app-data",
                "reference-app.social-inbox-trust-annotations",
                "migration.social-mail-preview",
            )
        ),
    }
    details = {
        "checks": checks,
        "redaction": {
            "rawMessageBodiesExcluded": True,
            "rawFetchedContentExcluded": True,
            "rawRequestBodiesExcluded": True,
            "rawSignaturesExcluded": True,
            "privateInsertUrisExcluded": True,
            "privateIdentityMaterialExcluded": True,
            "tokensExcluded": True,
            "localPathsExcluded": True,
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "migration.social-mail-preview",
            root_consequence(settings, "fail"),
            True,
            "Social/mail migration preview evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "migration.social-mail-preview",
        "pass",
        True,
        "Social/mail migration preview evidence passed.",
        source,
        details,
    )

def collect_legacy_plugin_migration_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    guide_path = workspace / "docs/legacy-plugin-migration-guide.md"
    plugin_status_path = workspace / "docs/plugin-system.md"
    portal_path = workspace / "docs/app-platform-developer-portal.md"
    beta_limits_path = workspace / "docs/app-platform-beta-known-limitations.md"
    guide_text = read_source(guide_path)
    guide_lower = guide_text.lower()
    developer_docs_text = read_source(portal_path) + "\n" + read_source(beta_limits_path)
    checks = {
        "guideExists": guide_path.is_file(),
        "oldRuntimeRemoved": "old plugin runtime" in guide_lower and "removed" in guide_lower,
        "noOldPluginAbiCompatibility": "old plugin ABI compatibility" in guide_text,
        "noFcpPluginCommandCompatibility": "old FCP plugin command compatibility" in guide_text,
        "webOfTrustMigration": "WebOfTrust-like" in guide_text or "WoT-like" in guide_text,
        "freetalkSoneMigration": "Freetalk/Sone-like" in guide_text,
        "freemailMigration": "Freemail-like" in guide_text,
        "trustGraphPreview": "Trust Graph Preview" in guide_text
        or "Trust Graph Local RC" in guide_text,
        "socialInboxReference": "Social Inbox RC" in guide_text
        or "Social Inbox reference" in guide_text,
        "appVault": "app vault" in guide_lower or "AppVault" in guide_text,
        "appData": "app data" in guide_lower or "app-data" in guide_lower,
        "contentSubscriptions": "content subscriptions" in guide_lower,
        "appServiceGrants": "app-service grant" in guide_lower,
        "signedCatalog": "signed catalog" in guide_lower,
        "reviewGovernance": "review receipt" in guide_lower
        or "review governance" in guide_lower,
        "pluginSystemLinksGuide": "legacy-plugin-migration-guide.md" in read_source(plugin_status_path),
        "developerOrBetaDocsLinkGuide": "legacy-plugin-migration-guide.md" in developer_docs_text,
    }
    details = {
        "guide": display_path(guide_path, workspace),
        "linkedDocs": [
            display_path(plugin_status_path, workspace),
            display_path(portal_path, workspace),
            display_path(beta_limits_path, workspace),
        ],
        "checks": checks,
        "redaction": {
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "rawBodiesExcluded": True,
            "rawSignaturesExcluded": True,
            "localPathsExcluded": True,
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "legacy-plugin.migration-guide",
            root_consequence(settings, "fail"),
            True,
            "Legacy plugin migration guide evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-plugin.migration-guide",
        "pass",
        True,
        "Legacy plugin migration guide evidence passed.",
        source,
        details,
    )

def plugin_migration_paths() -> tuple[Path, ...]:
    return (
        PLUGIN_MIGRATION_COOKBOOK_PATH,
        PLUGIN_MIGRATION_TEMPLATE_PATH,
        *PLUGIN_MIGRATION_EXAMPLE_PATHS,
    )

def plugin_migration_allowed_path(value: str) -> bool:
    normalized = value.replace("\\", "/").rstrip("/")
    return normalized in {
        "/app/node",
        "/content",
        "/queue",
        "/welcome",
    } or normalized.startswith(
        (
            "/api/",
            "/apps/",
            "/app-data/",
            "/app/node/",
            "/content/",
            "/queue/",
            "/platform/",
            "/operator/",
            "/trust-graph/",
            "/docs/",
            "/static/",
            "/src/",
            "/welcome/",
            "/.well-known/",
        )
    )

def plugin_migration_has_disallowed_local_path(text: str) -> bool:
    for match in PLUGIN_MIGRATION_FILE_URI_PATH_RE.finditer(text):
        path_value = urllib.parse.unquote(match.group("path")).replace("\\", "/")
        if not plugin_migration_allowed_path(path_value):
            return True
    for pattern in (WINDOWS_UNC_PATH_RE, WINDOWS_DRIVE_PATH_RE, ABSOLUTE_PATH_RE):
        for match in pattern.finditer(text):
            if not plugin_migration_allowed_path(match.group(0)):
                return True
    return False

def plugin_migration_text_for_general_redaction(text: str) -> str:
    return PLUGIN_MIGRATION_SAFE_URI_PLACEHOLDER_RE.sub("<safe-placeholder-uri>", text)

def plugin_migration_redaction_findings_for_text(
    text: str, workspace: Path, relative_path: str
) -> list[dict[str, str]]:
    checks = (
        ("private insert URI", PLUGIN_MIGRATION_PRIVATE_INSERT_URI_RE),
        ("private key", PLUGIN_MIGRATION_PRIVATE_KEY_RE),
        ("browser session token", PLUGIN_MIGRATION_BROWSER_SESSION_TOKEN_RE),
        ("app token", PLUGIN_MIGRATION_TOKEN_ASSIGNMENT_RE),
        ("authorization header", PLUGIN_MIGRATION_AUTH_HEADER_RE),
        ("raw migration artifact", PLUGIN_MIGRATION_RAW_ARTIFACT_RE),
    )
    findings: list[dict[str, str]] = []
    for kind, pattern in checks:
        if pattern.search(text):
            findings.append({"path": relative_path, "kind": kind})
    for kind in production_security_redaction_findings(
        plugin_migration_text_for_general_redaction(text),
        workspace,
    ):
        findings.append({"path": relative_path, "kind": kind})
    if plugin_migration_has_disallowed_local_path(text):
        findings.append({"path": relative_path, "kind": "local path"})
    return sorted({(finding["path"], finding["kind"]): finding for finding in findings}.values(), key=str)

def plugin_migration_redaction_summary(workspace: Path) -> dict[str, Any]:
    document_findings: list[dict[str, str]] = []
    for relative_path in plugin_migration_paths():
        path = workspace / relative_path
        if path.is_file():
            document_findings.extend(
                plugin_migration_redaction_findings_for_text(
                    read_source(path),
                    workspace,
                    relative_path.as_posix(),
                )
            )
    safe_fixture_path = (
        workspace
        / "tools/release-certification/fixtures/plugin-migration-redaction-safe.json"
    )
    safe_fixture_findings = (
        plugin_migration_redaction_findings_for_text(
            read_source(safe_fixture_path),
            workspace,
            "tools/release-certification/fixtures/plugin-migration-redaction-safe.json",
        )
        if safe_fixture_path.is_file()
        else [{"path": display_path(safe_fixture_path, workspace), "kind": "missing safe fixture"}]
    )
    negative_fixture_results: dict[str, dict[str, Any]] = {}
    negative_fixture_findings: list[dict[str, Any]] = []
    for relative_path, expected_kind in PLUGIN_MIGRATION_REDACTION_FIXTURE_EXPECTATIONS.items():
        path = workspace / relative_path
        findings = (
            plugin_migration_redaction_findings_for_text(
                read_source(path), workspace, relative_path
            )
            if path.is_file()
            else [{"path": relative_path, "kind": "missing fixture"}]
        )
        kinds = sorted({finding["kind"] for finding in findings})
        negative_fixture_results[relative_path] = {
            "expectedKind": expected_kind,
            "detectedKinds": kinds,
            "passes": expected_kind in kinds,
        }
        if not negative_fixture_results[relative_path]["passes"]:
            negative_fixture_findings.append(
                {
                    "path": relative_path,
                    "kind": "negative redaction fixture failed",
                    "expectedKind": expected_kind,
                    "detectedKinds": kinds,
                }
            )
    return {
        "documentFindings": document_findings,
        "safeFixtureFindings": safe_fixture_findings,
        "negativeFixtureResults": negative_fixture_results,
        "negativeFixtureFindings": negative_fixture_findings,
        "negativeFixturesPass": all(
            result["passes"] for result in negative_fixture_results.values()
        ),
    }

def collect_legacy_plugin_migration_finalization_evidence(
    settings: Settings,
) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    cookbook_path = workspace / PLUGIN_MIGRATION_COOKBOOK_PATH
    template_path = workspace / PLUGIN_MIGRATION_TEMPLATE_PATH
    example_paths = [workspace / path for path in PLUGIN_MIGRATION_EXAMPLE_PATHS]
    guide_path = workspace / "docs/legacy-plugin-migration-guide.md"
    freeze_policy_path = workspace / "docs/legacy-plugin-freeze-policy.md"
    plugin_system_path = workspace / "docs/plugin-system.md"
    portal_path = workspace / "docs/app-platform-developer-portal.md"
    third_party_program_path = workspace / "docs/third-party-developer-beta-program.md"
    submission_checklist_path = workspace / "docs/third-party-app-submission-checklist.md"
    workflow_path = workspace / "docs/app-store-submission-and-review-workflow.md"
    legacy_retirement_path = workspace / "docs/legacy-retirement-plan.md"
    app_service_docs_path = workspace / "docs/app-service-discovery-and-grants.md"
    trust_graph_docs_path = workspace / "docs/trust-graph-preview.md"
    social_inbox_docs_path = workspace / "docs/social-inbox-reference-app.md"
    go_no_go_docs_path = workspace / "docs/production-beta-go-no-go-dashboard.md"
    release_docs_path = workspace / "docs/release-certification.md"
    release_readme_path = workspace / "tools/release-certification/README.md"

    cookbook = read_source(cookbook_path)
    cookbook_lower = cookbook.lower()
    template_text = read_source(template_path)
    examples_text = "\n".join(read_source(path) for path in example_paths)
    examples_lower = examples_text.lower()
    guide_text = read_source(guide_path)
    freeze_policy_text = read_source(freeze_policy_path)
    plugin_system_text = read_source(plugin_system_path)
    portal_text = read_source(portal_path)
    third_party_program_text = read_source(third_party_program_path)
    submission_checklist_text = read_source(submission_checklist_path)
    workflow_text = read_source(workflow_path)
    legacy_retirement_text = read_source(legacy_retirement_path)
    app_service_docs_text = read_source(app_service_docs_path)
    trust_graph_docs_text = read_source(trust_graph_docs_path)
    social_inbox_docs_text = read_source(social_inbox_docs_path)
    go_no_go_docs_text = read_source(go_no_go_docs_path)
    release_docs_text = read_source(release_docs_path)
    release_readme_text = read_source(release_readme_path)
    linked_docs_text = "\n".join(
        [
            guide_text,
            freeze_policy_text,
            plugin_system_text,
            portal_text,
            third_party_program_text,
            submission_checklist_text,
            workflow_text,
            legacy_retirement_text,
            app_service_docs_text,
            trust_graph_docs_text,
            social_inbox_docs_text,
            go_no_go_docs_text,
        ]
    )
    linked_docs_lower = linked_docs_text.lower()
    release_docs_combined = release_docs_text + "\n" + release_readme_text
    runtime_violations = collect_plugin_runtime_surface_violations(workspace)
    redaction_summary = plugin_migration_redaction_summary(workspace)
    document_redaction_findings = redaction_summary["documentFindings"]
    safe_fixture_findings = redaction_summary["safeFixtureFindings"]
    negative_fixture_findings = redaction_summary["negativeFixtureFindings"]
    checks = {
        "cookbookExists": cookbook_path.is_file() and bool(cookbook.strip()),
        "migrationPlanTemplateExists": template_path.is_file() and bool(template_text.strip()),
        "examplesExist": all(path.is_file() and bool(read_source(path).strip()) for path in example_paths),
        "guideLinksCookbook": "legacy-plugin-migration-cookbook.md" in guide_text,
        "freezePolicyLinksCookbook": "legacy-plugin-migration-cookbook.md" in freeze_policy_text,
        "pluginSystemLinksCookbook": "legacy-plugin-migration-cookbook.md" in plugin_system_text,
        "developerPortalLinksCookbook": "legacy-plugin-migration-cookbook.md" in portal_text,
        "thirdPartyProgramLinksCookbook": "legacy-plugin-migration-cookbook.md" in third_party_program_text,
        "submissionChecklistLinksCookbook": "legacy-plugin-migration-cookbook.md"
        in submission_checklist_text,
        "workflowLinksCookbook": "legacy-plugin-migration-cookbook.md" in workflow_text,
        "legacyRetirementLinksCookbook": "legacy-plugin-migration-cookbook.md" in legacy_retirement_text,
        "releaseDocsListFinalization": "legacy-plugin.migration-finalization" in release_docs_combined,
        "goNoGoDocsListFinalization": "legacy-plugin.migration-finalization" in go_no_go_docs_text,
        "decisionTreePresent": "## decision tree" in cookbook_lower
        and "legacy plugin function" in cookbook_lower
        and "unsupported; no public-beta compatibility path is promised" in cookbook_lower,
        "migrationMatrixPresent": "## migration matrix" in cookbook_lower
        and all(
            marker in cookbook_lower
            for marker in (
                "old plugin ui",
                "plugin config and state",
                "plugin identity and secrets",
                "plugin trust score lookup",
                "old fcp plugin command",
            )
        ),
        "unsupportedForeverPresent": "## unsupported forever" in cookbook_lower
        and all(
            marker in cookbook_lower
            for marker in (
                "in-process daemon hooks",
                "old plugin abi/fcp command compatibility",
                "ambient localhost rpc",
                "raw fproxy scraping",
                "direct daemon internals",
                "private-key export",
                "unbounded crawling",
            )
        ),
        "webOfTrustMapsToTrustGraphLocalRc": "weboftrust-like" in cookbook_lower
        and "trust graph local rc" in cookbook_lower
        and "trust.score" in cookbook,
        "webOfTrustLocalOnlyLimitations": "local-only" in cookbook_lower
        and "global moderation" in cookbook_lower
        and "routing policy" in cookbook_lower
        and "peer-selection policy" in cookbook_lower,
        "webOfTrustGrantBoundary": "operator consent" in cookbook_lower
        and "service dependency and grant bundle approval" in cookbook_lower,
        "webOfTrustImportCapabilityBoundary": (
            "importing statements is a trust graph app capability" in cookbook_lower
        ),
        "webOfTrustDiagnosticsRedacted": (
            "must not include raw trust statements or signatures" in cookbook_lower
        ),
        "freetalkSoneMapsToSocialInboxRc": "freetalk/sone-like" in cookbook_lower
        and "social inbox rc" in cookbook_lower
        and "crypta.social.message.v1" in cookbook
        and "crypta.social.outbox.v1" in cookbook,
        "freetalkSoneNoProtocolCompatibility": (
            "not freetalk/sone protocol compatibility" in cookbook_lower
            or "no freetalk/sone protocol compatibility" in cookbook_lower
        )
        and "no daemon-core message store" in cookbook_lower
        and "no global moderation" in cookbook_lower,
        "freemailFutureMailPatternOnly": "freemail-like future mail app pattern" in cookbook_lower
        and "no implementation in pr-279" in cookbook_lower
        and "not encrypted mail transport" in cookbook_lower
        and "no freemail protocol compatibility" in cookbook_lower,
        "dataIdentitySubscriptionMigrationSafe": all(
            marker in cookbook_lower
            for marker in (
                "data, identity, and subscription preservation",
                "inventory old plugin state",
                "define app-data namespaces and schema versions",
                "support dry-run mode",
                "provide backup/export before destructive migration",
                "avoid private identity export",
                "avoid private insert uri persistence",
                "bind operator consent",
                "document what cannot be migrated automatically",
            )
        ),
        "migrationPlanSchemaTemplate": all(
            marker in template_text
            for marker in (
                "legacyPluginId",
                "newAppId",
                "stateClasses",
                "manifestCapabilities",
                "appDataNamespaces",
                "contentSubscriptions",
                "identityGrants",
                "appServiceDependencies",
                "migrationSteps",
                "backupRestorePolicy",
                "reviewEvidence",
                "redactionPolicy",
                "knownNonGoals",
            )
        ),
        "appServiceDependencyExamplesPresent": "app-service dependency examples" in cookbook_lower
        and "provider unavailable" in cookbook_lower
        and "grant revoked or expired" in cookbook_lower
        and "provider descriptor changed" in cookbook_lower
        and "no app-service request bodies or tokens" in cookbook_lower
        and "trust.score" in examples_text,
        "pluginAuthorBetaSubmissionFlowPresent": "beta submission flow" in cookbook_lower
        and all(
            command in cookbook
            for command in (
                "crypta-app init",
                "crypta-app test",
                "crypta-app ui lint",
                "crypta-app compat verify",
                "crypta-app pack",
                "crypta-app submission create",
                "crypta-app submission verify",
                "crypta-app submission pre-review",
            )
        ),
        "legacyAdminMaintenanceOnlyBoundaryPresent": "maintenance-only" in linked_docs_lower
        and "legacy admin" in linked_docs_lower,
        "fproxyBrowseRetainedBoundaryPresent": "fproxy browse remains retained" in linked_docs_lower
        and "does not create a new plugin api" in linked_docs_lower
        and "retained browse does not create a new plugin api" in linked_docs_lower,
        "oldPluginCompatibilityAbsent": "old plugin abi/fcp/runtime/toadlet/admin surfaces are not used"
        in cookbook_lower
        and "unsupportedpluginmessage" in linked_docs_lower
        and "no compatibility shim" in cookbook_lower,
        "wotExamplePresent": "trust graph local rc" in examples_lower
        and "trust.score" in examples_text,
        "socialExamplePresent": "social inbox rc" in examples_lower
        and "crypta.social.message.v1" in examples_text,
        "mailExamplePresent": "future mail" in examples_lower
        and "not implemented in pr-279" in examples_lower,
        "contentPublishingExamplePresent": "content.insert.app-document" in examples_text
        and "private insert uris" in examples_lower,
        "sourceSurfaceAuditPasses": not runtime_violations,
        "redactionChecksPass": not document_redaction_findings
        and not safe_fixture_findings
        and redaction_summary["negativeFixturesPass"],
    }
    details: dict[str, Any] = {
        "sources": {
            "cookbook": display_path(cookbook_path, workspace),
            "template": display_path(template_path, workspace),
            "examples": [display_path(path, workspace) for path in example_paths],
            "linkedDocs": [
                display_path(guide_path, workspace),
                display_path(freeze_policy_path, workspace),
                display_path(plugin_system_path, workspace),
                display_path(portal_path, workspace),
                display_path(third_party_program_path, workspace),
                display_path(submission_checklist_path, workspace),
                display_path(workflow_path, workspace),
                display_path(legacy_retirement_path, workspace),
                display_path(app_service_docs_path, workspace),
                display_path(trust_graph_docs_path, workspace),
                display_path(social_inbox_docs_path, workspace),
                display_path(go_no_go_docs_path, workspace),
                display_path(release_docs_path, workspace),
                display_path(release_readme_path, workspace),
            ],
        },
        "checks": checks,
        "runtimeSurfaceViolations": runtime_violations,
        "redaction": {
            "documentsScanned": [path.as_posix() for path in plugin_migration_paths()],
            "safeFixtureFindings": safe_fixture_findings,
            "negativeFixtureResults": redaction_summary["negativeFixtureResults"],
            "negativeFixtureFindings": negative_fixture_findings,
            "documentFindings": document_redaction_findings,
        },
    }
    if document_redaction_findings or safe_fixture_findings or negative_fixture_findings:
        details["redactionFindings"] = (
            document_redaction_findings
            + safe_fixture_findings
            + negative_fixture_findings
        )
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "legacy-plugin.migration-finalization",
            root_consequence(settings, "fail"),
            True,
            "Legacy plugin migration finalization evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-plugin.migration-finalization",
        "pass",
        True,
        "Legacy plugin migration finalization evidence passed.",
        source,
        details,
    )

def collect_legacy_plugin_social_inbox_spike_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    app_dir = workspace / "apps/social-inbox"
    manifest_path = app_dir / "src/staged/cryptad-app.properties.template"
    if not manifest_path.is_file():
        manifest_path = app_dir / "build/cryptad-app/social-inbox/cryptad-app.properties"
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    errors: list[str] = []
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    social_app_js = read_source(app_dir / "src/staged/static/app.js")
    social_readme = read_source(app_dir / "README.md")
    social_doc = read_source(workspace / "docs/social-inbox-reference-app.md")
    docs_text = social_readme + "\n" + social_doc
    direct_local_endpoint_reference = has_direct_local_endpoint_reference(social_app_js)
    checks = {
        "appExists": app_dir.is_dir(),
        "manifestPresent": manifest_path.is_file(),
        "manifestDeclaresExpectedCapabilities": SOCIAL_INBOX_PERMISSIONS.issubset(
            manifest_permissions
        ),
        "manifestRequestsTrustScoreService": (
            manifest.get("app.services.requests") == "trust-score"
            and manifest.get("app.service-request.trust-score.provider") == "trust-graph"
            and manifest.get("app.service-request.trust-score.service") == "trust.score"
            and manifest.get("app.service-request.trust-score.scopes") == "score.read"
            and manifest.get("app.service-request.trust-score.contexts") == "message-author"
        ),
        "usesPlatformMediatedServiceGrant": (
            "CryptaPlatform.services.get" in social_app_js
            and "CryptaPlatform.services.bundles.request" in social_app_js
            and "CryptaPlatform.services.invoke" in social_app_js
            and "trustScoreProviderAppId = \"trust-graph\"" in social_app_js
            and "trustScoreServiceId = \"trust.score\"" in social_app_js
            and "CryptaPlatform.trust.score" not in social_app_js
            and not direct_local_endpoint_reference
        ),
        "noDirectLocalEndpointReference": not direct_local_endpoint_reference,
        "docsFrameSpikeNonGoals": social_inbox_docs_frame_spike_non_goals(docs_text),
    }
    details = {
        "appId": "social-inbox",
        "manifest": display_path(manifest_path, workspace),
        "expectedPermissions": sorted(SOCIAL_INBOX_PERMISSIONS),
        "declaredPermissions": sorted(manifest_permissions),
        "checks": checks,
        "redaction": {
            "ambientLocalhostTrustExcluded": not direct_local_endpoint_reference,
            "rawMessageBodiesExcluded": True,
            "rawFetchedContentExcluded": True,
            "rawSignaturesExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "localPathsExcluded": True,
        },
    }
    errors.extend(name for name, passed in checks.items() if not passed)
    if errors:
        return EvidenceItem(
            "legacy-plugin.social-inbox-spike",
            root_consequence(settings, "fail"),
            True,
            "Legacy plugin Social Inbox RC migration evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-plugin.social-inbox-spike",
        "pass",
        True,
        "Legacy plugin Social Inbox RC migration evidence passed.",
        source,
        details,
    )

def repo_relative_path(path: Path, workspace_root: Path) -> str:
    try:
        return path.resolve().relative_to(workspace_root.resolve()).as_posix()
    except ValueError:
        return display_path(path, workspace_root)

def is_main_java_source(path: Path, workspace_root: Path) -> bool:
    if path.suffix != ".java":
        return False
    relative = repo_relative_path(path, workspace_root)
    parts = set(Path(relative).parts)
    if parts.intersection({".git", ".gradle", "build"}):
        return False
    return "/src/main/java/" in f"/{relative}"

def collect_plugin_runtime_surface_violations(workspace: Path) -> list[dict[str, str]]:
    allowed_runtime_command_files = {
        "adapter-fcp/src/main/java/network/crypta/clients/fcp/FCPMessage.java",
        "adapter-fcp/src/main/java/network/crypta/clients/fcp/UnsupportedPluginMessage.java",
    }
    old_command_names = (
        "FCPPluginMessage",
        "GetPluginInfo",
        "LoadPlugin",
        "ReloadPlugin",
        "RemovePlugin",
    )
    forbidden_declaration_re = re.compile(
        r"\b(?:class|interface|enum|record)\s+"
        r"(?:PluginManager|PluginRespirator|PluginTalker|PluginInfoWrapper|"
        r"PluginConnection|PluginToadlet|FCPPluginMessage|LoadPlugin|ReloadPlugin|"
        r"RemovePlugin|GetPluginInfo)\b"
    )
    violations: list[dict[str, str]] = []
    for java_file in workspace.rglob("*.java"):
        if not is_main_java_source(java_file, workspace):
            continue
        relative = repo_relative_path(java_file, workspace)
        text = java_source_without_comments(read_source(java_file))
        if re.search(r"^\s*package\s+network\.crypta\.pluginmanager\b", text, re.MULTILINE):
            violations.append({"path": relative, "reason": "pluginmanager package"})
        if "/pluginmanager/" in f"/{relative}":
            violations.append({"path": relative, "reason": "pluginmanager source path"})
        if re.search(
            r"^\s*import\s+(?:static\s+)?network\.crypta\.pluginmanager\b",
            text,
            re.MULTILINE,
        ):
            violations.append({"path": relative, "reason": "pluginmanager import"})
        if forbidden_declaration_re.search(text):
            violations.append({"path": relative, "reason": "old plugin runtime declaration"})
        if PLUGIN_MIGRATION_COMPAT_SHIM_DECLARATION_RE.search(text):
            violations.append(
                {
                    "path": relative,
                    "reason": "legacy plugin compatibility shim declaration",
                }
            )
        if PLUGIN_MIGRATION_PLUGIN_ROUTE_LITERAL_RE.search(text) and (
            "Toadlet" in text or "register" in text or "LegacyAdmin" in text
        ):
            violations.append({"path": relative, "reason": "legacy plugin route registration"})
        if relative not in allowed_runtime_command_files and any(
            f'"{command_name}"' in text for command_name in old_command_names
        ):
            violations.append({"path": relative, "reason": "old plugin command runtime reference"})
    return violations

def collect_legacy_plugin_freeze_policy_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    plugin_status_path = workspace / "docs/plugin-system.md"
    freeze_policy_path = workspace / "docs/legacy-plugin-freeze-policy.md"
    migration_guide_path = workspace / "docs/legacy-plugin-migration-guide.md"
    portal_path = workspace / "docs/app-platform-developer-portal.md"
    beta_limits_path = workspace / "docs/app-platform-beta-known-limitations.md"
    release_docs_path = workspace / "docs/release-certification.md"
    unsupported_path = (
        workspace
        / "adapter-fcp/src/main/java/network/crypta/clients/fcp/UnsupportedPluginMessage.java"
    )
    fcp_message_path = workspace / "adapter-fcp/src/main/java/network/crypta/clients/fcp/FCPMessage.java"

    plugin_status = read_source(plugin_status_path)
    freeze_policy = read_source(freeze_policy_path)
    migration_guide = read_source(migration_guide_path)
    developer_docs = read_source(portal_path) + "\n" + read_source(beta_limits_path)
    release_docs = read_source(release_docs_path)
    unsupported_text = read_source(unsupported_path)
    fcp_message_text = read_source(fcp_message_path)
    combined_policy_docs = "\n".join(
        [plugin_status, freeze_policy, migration_guide, developer_docs, release_docs]
    )
    combined_policy_lower = combined_policy_docs.lower()
    plugin_status_lower = plugin_status.lower()
    freeze_policy_lower = freeze_policy.lower()
    freeze_policy_normalized = re.sub(r"\s+", " ", freeze_policy_lower)
    migration_guide_lower = migration_guide.lower()
    developer_docs_lower = developer_docs.lower()

    old_command_names = (
        "FCPPluginMessage",
        "GetPluginInfo",
        "LoadPlugin",
        "ReloadPlugin",
        "RemovePlugin",
    )
    command_mappings = {
        command_name: bool(
            re.search(
                rf'case\s+"{re.escape(command_name)}"\s*->\s*new\s+UnsupportedPluginMessage',
                fcp_message_text,
            )
        )
        for command_name in old_command_names
    }
    runtime_violations = collect_plugin_runtime_surface_violations(workspace)
    checks = {
        "pluginSystemPolicyExists": plugin_status_path.is_file(),
        "freezePolicyDocumentExists": freeze_policy_path.is_file(),
        "pluginSystemDeclaresFrozenRemoved": "removed" in plugin_status_lower
        and ("frozen" in plugin_status_lower or "freeze" in plugin_status_lower)
        and "production rc" in plugin_status_lower,
        "pluginSystemLinksFreezePolicy": "legacy-plugin-freeze-policy.md" in plugin_status,
        "freezePolicyDeclaresFrozenRemoved": "removed" in freeze_policy_lower
        and ("frozen" in freeze_policy_lower or "freeze" in freeze_policy_lower)
        and "production rc" in freeze_policy_lower,
        "freezePolicyDeclaresNoNewCoreApis": (
            "do not add new in-core plugin api" in freeze_policy_lower
            or "do not add new in-core plugin apis" in freeze_policy_lower
            or "do not add new daemon-core plugin api" in freeze_policy_lower
            or "do not add new daemon-core plugin apis" in freeze_policy_lower
        ),
        "freezePolicyDeclaresNoOldPluginAbiCompatibility": (
            "old plugin abi" in freeze_policy_lower
            and ("do not restore" in freeze_policy_lower or "removed" in freeze_policy_lower)
        ),
        "freezePolicyDeclaresNoOldFcpCommandCompatibility": (
            "old fcp plugin command compatibility" in freeze_policy_lower
            and ("do not restore" in freeze_policy_lower or "no old" in freeze_policy_lower)
        ),
        "freezePolicyKeepsUnsupportedBoundary": "unsupportedpluginmessage" in freeze_policy_lower
        and "deterministic unsupported" in freeze_policy_lower
        and "must not execute plugin code" in freeze_policy_lower,
        "freezePolicyDeclaresHistoricalDocsOnly": "docs/legacy" in freeze_policy_lower
        and "historical" in freeze_policy_lower
        and (
            "not current implementation commitments" in freeze_policy_normalized
            or "not an implementation commitment" in freeze_policy_normalized
        ),
        "noNewInCorePluginApis": "no new in-core plugin api" in plugin_status_lower
        or "no new in-core plugin apis" in plugin_status_lower
        or "do not add new in-core plugin api" in plugin_status_lower
        or "do not add new in-core plugin apis" in plugin_status_lower,
        "noOldPluginAbiCompatibility": "no old plugin abi compatibility" in combined_policy_lower
        or "not old plugin abi compatibility" in combined_policy_lower
        or (
            "old plugin abi compatibility" in combined_policy_lower
            and (
                "does not restore" in combined_policy_lower
                or "non-goals" in combined_policy_lower
            )
        ),
        "noOldFcpPluginCommandCompatibility": "no old fcp plugin command compatibility"
        in combined_policy_lower,
        "legacyDocsHistoricalOnly": "docs/legacy" in combined_policy_lower
        and "historical" in combined_policy_lower,
        "migrationGuideLinksFreezePolicy": "legacy-plugin-freeze-policy.md" in migration_guide,
        "appPlatformDocsLinkMigrationOrFreeze": "legacy-plugin-freeze-policy.md" in developer_docs
        or "legacy-plugin-migration-guide.md" in developer_docs,
        "appPlatformDocsLinkFreezePolicy": "legacy-plugin-freeze-policy.md" in developer_docs,
        "releaseDocsListFreezeEvidence": "legacy-plugin.freeze-policy" in release_docs,
        "outOfProcessMigrationMechanisms": all(
            marker in combined_policy_lower
            for marker in (
                "out-of-process app",
                "platform api",
                "signed catalog",
                "appvault",
                "content subscriptions",
                "durable app data",
                "trust graph local rc",
                "app-service grant",
            )
        ),
        "nonGoalNotFullWot": "not full wot" in combined_policy_lower
        or "not a full web of trust" in combined_policy_lower,
        "nonGoalNoOldWebOfTrustPlugin": "not old weboftrust plugin" in combined_policy_lower
        or "no old weboftrust plugin" in combined_policy_lower
        or "does not provide old weboftrust" in combined_policy_lower,
        "nonGoalNoFreetalkSoneFreemail": "freetalk" in combined_policy_lower
        and "sone" in combined_policy_lower
        and "freemail" in combined_policy_lower
        and "compatibility" in combined_policy_lower,
        "nonGoalNoEncryptedMailTransport": "not encrypted mail transport" in combined_policy_lower
        or "not encrypted email delivery" in combined_policy_lower,
        "nonGoalNoDaemonCoreSocialMailProtocol": (
            "not a daemon-core social" in combined_policy_lower
            or "no daemon-core social" in combined_policy_lower
        )
        and ("mail" in combined_policy_lower or "message protocol" in combined_policy_lower),
        "unsupportedPluginHandlerExists": unsupported_path.is_file(),
        "unsupportedPluginMessageRejectsDeterministically": "Plugin system has been removed"
        in unsupported_text
        and "ProtocolErrorMessage.INVALID_MESSAGE" in unsupported_text
        and "handler.send" in unsupported_text,
        "fcpPluginCommandsMapToUnsupported": all(command_mappings.values()),
        "noRuntimePluginSurfaceViolations": not runtime_violations,
    }
    details = {
        "policyDocs": [
            display_path(plugin_status_path, workspace),
            display_path(freeze_policy_path, workspace),
            display_path(migration_guide_path, workspace),
            display_path(portal_path, workspace),
            display_path(beta_limits_path, workspace),
            display_path(release_docs_path, workspace),
        ],
        "allowedRuntimeCompatibilityFiles": [
            display_path(unsupported_path, workspace),
            display_path(fcp_message_path, workspace),
        ],
        "commandMappingsToUnsupportedHandler": command_mappings,
        "runtimeSurfaceViolations": runtime_violations,
        "checks": checks,
        "redaction": {
            "queryStringsExcluded": True,
            "requestBodiesExcluded": True,
            "formPasswordsExcluded": True,
            "tokensExcluded": True,
            "privateInsertUrisExcluded": True,
            "rawDiagnosticsExcluded": True,
            "rawFetchedContentExcluded": True,
            "rawAppDataExcluded": True,
            "rawSignaturesExcluded": True,
            "absoluteLocalPathsExcluded": True,
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "legacy-plugin.freeze-policy",
            root_consequence(settings, "fail"),
            True,
            "Legacy plugin freeze policy evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "legacy-plugin.freeze-policy",
        "pass",
        True,
        "Legacy plugin freeze policy and source-surface checks passed.",
        source,
        details,
    )
