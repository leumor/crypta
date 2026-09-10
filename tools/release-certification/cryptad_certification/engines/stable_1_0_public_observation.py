"""Fail-closed HTTPS transport for Stable 1.0 public observation.

The observer must retrieve public bytes without trusting proxies, a second DNS lookup, or an
unbounded response body.  This module deliberately uses only the Python standard library so the
protected workflow can import it from the exact checked-out candidate.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
from typing import Any, Mapping
from urllib.parse import urljoin, urlsplit, urlunsplit


API_DOCUMENT_LIMIT = 4 * 1024 * 1024
PUBLIC_DOCUMENT_LIMIT = 32 * 1024 * 1024
PUBLIC_SIGNATURE_LIMIT = 1024 * 1024
_CHUNK_SIZE = 64 * 1024


class PublicObservationTransportError(RuntimeError):
    """One public-safe failure at the read-only observation transport boundary."""


class PublicObservationNotFound(PublicObservationTransportError):
    """The selected public resource explicitly returned HTTP 404."""


@dataclass(frozen=True)
class ObservedBytes:
    """The bounded size and SHA-256 identity observed for one public object."""

    size: int
    digest: str


def _canonical_https_uri(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip() or "\\" in value:
        raise PublicObservationTransportError("public-uri-invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port or 443
    except ValueError as exc:
        raise PublicObservationTransportError("public-uri-invalid") from exc
    path_parts = parsed.path.split("/")[1:]
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port != 443
        or any(character.isspace() or ord(character) < 32 for character in value)
        or any(part in {".", ".."} for part in path_parts)
        or any(not part for part in path_parts[:-1])
    ):
        raise PublicObservationTransportError("public-uri-invalid")
    try:
        address = ipaddress.ip_address(parsed.hostname)
        hostname = str(address)
        authority = f"[{hostname}]" if address.version == 6 else hostname
    except ValueError:
        try:
            hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise PublicObservationTransportError("public-uri-invalid") from exc
        if not hostname or "." not in hostname:
            raise PublicObservationTransportError("public-uri-invalid")
        authority = hostname
    canonical = urlunsplit(("https", authority, parsed.path, parsed.query, ""))
    if canonical != value:
        raise PublicObservationTransportError("public-uri-not-canonical")
    return canonical


def _global_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        rows = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise PublicObservationTransportError("public-host-resolution-failed") from exc
    addresses: list[str] = []
    for row in rows:
        try:
            address = str(ipaddress.ip_address(row[4][0]))
        except ValueError as exc:
            raise PublicObservationTransportError("public-host-resolution-invalid") from exc
        if not ipaddress.ip_address(address).is_global:
            raise PublicObservationTransportError("public-host-resolution-not-global")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise PublicObservationTransportError("public-host-resolution-empty")
    return tuple(addresses)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str, port: int, timeout: float) -> None:
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._address = address

    def connect(self) -> None:
        if self._tunnel_host is not None:
            raise OSError("HTTPS tunnels are forbidden")
        raw = socket.create_connection((self._address, self.port), self.timeout)
        try:
            peer = ipaddress.ip_address(raw.getpeername()[0])
            if peer != ipaddress.ip_address(self._address) or not peer.is_global:
                raise OSError("connected peer differs from pinned public address")
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _content_length(response: http.client.HTTPResponse) -> int | None:
    value = response.getheader("Content-Length")
    if value is None:
        return None
    try:
        length = int(value)
    except ValueError as exc:
        raise PublicObservationTransportError("http-content-length-invalid") from exc
    if length < 0:
        raise PublicObservationTransportError("http-content-length-invalid")
    return length


class PublicObservationTransport:
    """Address-pinned HTTPS reader with explicit redirects and bounded streaming."""

    def __init__(self, *, timeout: float = 60.0) -> None:
        self._timeout = timeout

    def json_document(
        self,
        uri: str,
        *,
        headers: Mapping[str, str] | None = None,
        maximum_bytes: int = API_DOCUMENT_LIMIT,
    ) -> dict[str, Any]:
        """Read one bounded JSON object while forbidding redirects."""

        raw, _observed = self._read(
            uri,
            headers=headers,
            maximum_bytes=maximum_bytes,
            exact_size=None,
            redirect_budget=0,
            retain=True,
            visited=frozenset(),
        )

        def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise PublicObservationTransportError("json-document-duplicate-field")
                result[key] = value
            return result

        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublicObservationTransportError("json-document-malformed") from exc
        if not isinstance(value, dict):
            raise PublicObservationTransportError("json-document-not-object")
        return value

    def exact_digest(
        self,
        uri: str,
        expected_size: int,
        *,
        headers: Mapping[str, str] | None = None,
        redirect_budget: int = 1,
    ) -> ObservedBytes:
        """Stream one exact-size object and return only its observed identity."""

        if not isinstance(expected_size, int) or expected_size < 0:
            raise PublicObservationTransportError("expected-size-invalid")
        _raw, observed = self._read(
            uri,
            headers=headers,
            maximum_bytes=expected_size,
            exact_size=expected_size,
            redirect_budget=redirect_budget,
            retain=False,
            visited=frozenset(),
        )
        return observed

    def bounded_digest(
        self,
        uri: str,
        *,
        maximum_bytes: int = PUBLIC_DOCUMENT_LIMIT,
        headers: Mapping[str, str] | None = None,
        redirect_budget: int = 1,
    ) -> ObservedBytes:
        """Stream one bounded document and return only its observed identity."""

        _raw, observed = self._read(
            uri,
            headers=headers,
            maximum_bytes=maximum_bytes,
            exact_size=None,
            redirect_budget=redirect_budget,
            retain=False,
            visited=frozenset(),
        )
        return observed

    def _read(
        self,
        uri: str,
        *,
        headers: Mapping[str, str] | None,
        maximum_bytes: int,
        exact_size: int | None,
        redirect_budget: int,
        retain: bool,
        visited: frozenset[str],
    ) -> tuple[bytes, ObservedBytes]:
        if not isinstance(maximum_bytes, int) or maximum_bytes < 0:
            raise PublicObservationTransportError("response-bound-invalid")
        canonical = _canonical_https_uri(uri)
        if canonical in visited:
            raise PublicObservationTransportError("http-redirect-cycle")
        parsed = urlsplit(canonical)
        host = str(parsed.hostname)
        port = parsed.port or 443
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        failures: list[BaseException] = []
        for address in _global_addresses(host, port):
            connection = _PinnedHTTPSConnection(host, address, port, self._timeout)
            try:
                connection.request("GET", path, headers=dict(headers or {}))
                response = connection.getresponse()
                if 300 <= response.status < 400:
                    if redirect_budget <= 0:
                        raise PublicObservationTransportError("http-redirect-forbidden")
                    location = response.getheader("Location")
                    if not isinstance(location, str) or not location:
                        raise PublicObservationTransportError("http-redirect-invalid")
                    redirected = _canonical_https_uri(urljoin(canonical, location))
                    safe_headers = {
                        key: value
                        for key, value in dict(headers or {}).items()
                        if key.lower() not in {"authorization", "cookie"}
                    }
                    return self._read(
                        redirected,
                        headers=safe_headers,
                        maximum_bytes=maximum_bytes,
                        exact_size=exact_size,
                        redirect_budget=redirect_budget - 1,
                        retain=retain,
                        visited=visited | {canonical},
                    )
                if response.status == 404:
                    raise PublicObservationNotFound("http-response-not-found")
                if response.status != 200:
                    raise PublicObservationTransportError("http-response-not-success")
                declared = _content_length(response)
                if exact_size is not None and declared is not None and declared != exact_size:
                    raise PublicObservationTransportError("http-content-length-differs")
                if declared is not None and declared > maximum_bytes:
                    raise PublicObservationTransportError("http-response-too-large")
                digest = hashlib.sha256()
                chunks: list[bytes] = []
                size = 0
                while True:
                    chunk = response.read(min(_CHUNK_SIZE, maximum_bytes + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > maximum_bytes:
                        raise PublicObservationTransportError("http-response-too-large")
                    digest.update(chunk)
                    if retain:
                        chunks.append(chunk)
                if exact_size is not None and size != exact_size:
                    raise PublicObservationTransportError("http-response-size-differs")
                observed = ObservedBytes(size, "sha256:" + digest.hexdigest())
                return (b"".join(chunks) if retain else b""), observed
            except PublicObservationTransportError:
                raise
            except (OSError, http.client.HTTPException, ValueError) as exc:
                failures.append(exc)
            finally:
                connection.close()
        raise PublicObservationTransportError("https-request-unavailable") from (
            failures[-1] if failures else None
        )


def github_release_identity(
    value: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    build: str,
    commit: str,
) -> dict[str, Any]:
    """Validate and return the exact public GitHub Release identity to record."""

    body = value.get("body")
    body = body if isinstance(body, str) else ""
    notes_digest = "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()
    expected = {
        "releaseId": receipt.get("releaseId"),
        "publicUrl": receipt.get("publicUrl"),
        "name": f"Cryptad Stable 1.0 (v{build})",
        "tagName": f"v{build}",
        "targetCommitish": commit,
        "draft": False,
        "prerelease": False,
        "releaseNotesDigest": receipt.get("releaseNotesDigest"),
        "status": "observed-exact",
    }
    actual = {
        "releaseId": value.get("id"),
        "publicUrl": value.get("html_url"),
        "name": value.get("name"),
        "tagName": value.get("tag_name"),
        "targetCommitish": value.get("target_commitish"),
        "draft": value.get("draft"),
        "prerelease": value.get("prerelease"),
        "releaseNotesDigest": notes_digest,
        "status": "observed-exact",
    }
    if (
        value.get("draft") is not False
        or value.get("prerelease") is not False
        or actual != expected
    ):
        raise PublicObservationTransportError("github-release-identity-differs")
    return actual


def catalog_signature_uri(catalog_uri: str) -> str:
    """Return the canonical detached-signature sibling for one Stable catalog URI."""

    canonical = _canonical_https_uri(catalog_uri)
    if canonical.endswith("/cryptad-app-catalog.properties"):
        signature_uri = (
            canonical[: -len("cryptad-app-catalog.properties")]
            + "cryptad-app-catalog.signature"
        )
    elif canonical.endswith("/first-party-catalog.properties"):
        signature_uri = (
            canonical[: -len("first-party-catalog.properties")]
            + "first-party-catalog.sig"
        )
    else:
        raise PublicObservationTransportError("catalog-signature-uri-unsupported")
    return _canonical_https_uri(signature_uri)


def github_annotated_tag_identity(
    reference: Mapping[str, Any],
    value: Mapping[str, Any],
    *,
    build: str,
    commit: str,
) -> dict[str, Any]:
    """Validate and return the exact public annotated-tag identity to record."""

    tag_name = f"v{build}"
    tag_object = reference.get("object")
    target = value.get("object")
    if (
        reference.get("ref") != f"refs/tags/{tag_name}"
        or not isinstance(tag_object, Mapping)
        or tag_object.get("type") != "tag"
        or not isinstance(tag_object.get("sha"), str)
        or value.get("sha") != tag_object.get("sha")
        or value.get("tag") != tag_name
        or not isinstance(target, Mapping)
        or target.get("type") != "commit"
        or target.get("sha") != commit
    ):
        raise PublicObservationTransportError("github-annotated-tag-identity-differs")
    return {
        "name": tag_name,
        "targetCommit": commit,
        "annotated": True,
        "status": "observed-exact",
    }


def github_release_assets(
    values: Any,
    expected: list[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    """Return the exact uploaded GitHub asset map without hiding duplicate names."""

    if not isinstance(values, list) or not all(isinstance(row, dict) for row in values):
        raise PublicObservationTransportError("github-release-assets-malformed")
    names = [row.get("name") for row in values]
    if any(not isinstance(name, str) for name in names) or len(names) != len(set(names)):
        raise PublicObservationTransportError("github-release-assets-ambiguous")
    expected_by_name = {str(row.get("name")): row for row in expected}
    if set(names) != set(expected_by_name):
        raise PublicObservationTransportError("github-release-asset-allowlist-differs")
    result: dict[str, Mapping[str, Any]] = {}
    for row in values:
        name = str(row["name"])
        planned = expected_by_name[name]
        api_digest = row.get("digest")
        if (
            row.get("state") != "uploaded"
            or row.get("size") != planned.get("sizeBytes")
            or not isinstance(row.get("browser_download_url"), str)
            or (api_digest is not None and api_digest != planned.get("digest"))
        ):
            raise PublicObservationTransportError("github-release-asset-metadata-differs")
        result[name] = row
    return result
