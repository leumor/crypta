"""Owned loopback HTTP source for exact synthetic catalogs and real fallback traffic.

The finite object roster is captured before launch. No filesystem paths or request headers are
logged, no arbitrary source can be fetched, and mutation changes only this server's responses.
"""
from __future__ import annotations

from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from catalog_origin_lifecycle import LifecycleFailure


class FixtureServer:
    def __init__(self, revisions):
        if not {"initial", "update", "switch"} <= set(revisions) <= {"initial", "update", "switch", "conflict", "beta", "publisher", "equivalent", "originUpdate", "untrusted", "deny"}:
            raise LifecycleFailure("catalog-fixture-roster-invalid")
        self.revisions = {}
        for name, objects in revisions.items():
            if (set(objects) != {"catalog", "signature"}
                    or any(type(value) is not bytes or not 0 < len(value) <= 8 * 1024 * 1024
                           for value in objects.values())):
                raise LifecycleFailure("catalog-fixture-objects-invalid")
            self.revisions[name] = dict(objects)
        self.selected = "initial"
        self.alternate_selected = "switch"
        self.primary_available = True
        self.mirror_mode = "exact"
        self.requests = Counter()
        self.lock = threading.Lock()
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                names = {"cryptad-app-catalog.properties": "catalog",
                         "cryptad-app-catalog.signature": "signature"}
                pieces = self.path.split("/")
                if len(pieces) != 3 or pieces[1] not in {"primary", "mirror", "alternate", "conflict", "beta", "publisher", "equivalent", "originUpdate", "untrusted", "deny"} or pieces[2] not in names:
                    self.send_error(404)
                    return
                source, member = pieces[1], names[pieces[2]]
                with owner.lock:
                    owner.requests[(source, member)] += 1
                    available = source != "primary" or owner.primary_available
                    revision = {"alternate": owner.alternate_selected, "conflict": "conflict", "beta": "beta", "publisher": "publisher", "untrusted": "untrusted", "deny": "deny", "equivalent": "equivalent", "originUpdate": "originUpdate"}.get(source, owner.selected)
                    if revision not in owner.revisions:
                        self.send_error(404)
                        return
                    if source == "mirror" and owner.mirror_mode == "stale":
                        revision = "initial"
                    body = owner.revisions[revision][member]
                    if source == "mirror" and owner.mirror_mode == "mismatch" and member == "signature":
                        body = owner.revisions["switch"][member]
                if not available:
                    self.send_response(503)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def uri(self, source):
        if source not in {"primary", "mirror", "alternate", "conflict", "beta", "publisher", "equivalent", "originUpdate", "untrusted", "deny"}:
            raise LifecycleFailure("catalog-fixture-source-invalid")
        return f"http://127.0.0.1:{self.server.server_port}/{source}/cryptad-app-catalog.properties"

    def counts(self):
        with self.lock:
            return {source + "/" + member: count for (source, member), count in sorted(self.requests.items())}

    def require_fetched(self, source, before):
        after = self.counts()
        if any(after.get(source + "/" + member, 0) <= before.get(source + "/" + member, 0)
               for member in ("catalog", "signature")):
            raise LifecycleFailure("catalog-mirror-traffic-not-observed")
        return after
