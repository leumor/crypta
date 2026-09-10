"""Thin CLI boundary between the private interop supervisor and pure evidence verification."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys

from . import cross_version_evidence as evidence
from .redaction import scan_value


def unique_members(items):
    """Reject ambiguous JSON in both selected inputs and measured journal entries."""
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('cross-version-duplicate-json-member')
        result[key] = value
    return result


def read(path, *, private=False, limit=4 * 1024 * 1024):
    if path is None:
        raise ValueError('cross-version-required-input-missing')
    path = Path(path)
    if (path.is_symlink() or any(p.is_symlink() for p in path.parents)
            or not path.is_file() or path.stat().st_size > limit):
        raise ValueError('cross-version-input-path-or-size-invalid')
    if private and (path.stat().st_mode & 0o077 or path.stat().st_uid != os.geteuid()):
        raise ValueError('cross-version-private-input-permissions-invalid')
    return json.loads(path.read_bytes(), object_pairs_hook=unique_members)


def adapter(name, *, protected=False):
    # Adapter selection is fixed by the installed runner, never a manifest-supplied script.
    directory = (Path(__file__).resolve().parents[1] / 'protected' if protected
                 else Path(__file__).resolve().parents[2] / 'interop')
    path = directory / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    sys.path.insert(0, str(directory))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def fresh_output(directory):
    """Reject unusable output before any side effect on a selected node."""
    if directory is None:
        raise ValueError('cross-version-output-required')
    directory = Path(directory)
    if directory.exists() or directory.is_symlink() or any(p.is_symlink() for p in directory.parents):
        raise ValueError('cross-version-output-must-be-new')
    if not directory.parent.is_dir():
        raise ValueError('cross-version-output-parent-missing')
    return directory


def publish(directory, value, *, migration=None):
    """Create a fresh public component from fixed metadata, never copy private work files."""
    directory = fresh_output(directory)
    if scan_value(value):
        raise ValueError('cross-version-public-redaction-failed')
    if migration is not None:
        adapter('sharesite_observation', protected=True).validate_observation(migration)
    directory.mkdir(mode=0o700)
    with (directory / 'summary.json').open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
    if migration is not None:
        with (directory / 'sharesite-runtime-observation.json').open('x', encoding='utf-8') as stream:
            json.dump(migration, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write('\n')


def runtime_subcases(runtime):
    """Rebuild bounded subcase verdicts; supplementary observations never satisfy a gate.

    Only fixed case names and outcomes cross this boundary. Runtime implementation details,
    exception text, source paths, identifiers and private comparison values are not copied.
    """
    output = {"authentication": "not-independently-authenticated", "releaseEligible": False}
    states = {"observed", "not-observed", "pass", "fail", "failed", "partial", "complete", "incomplete", "cleanup-incomplete"}
    def selected(name, source, keys):
        if source is None:
            return
        if not isinstance(source, dict) or not set(source) <= set(keys):
            raise ValueError('cross-version-runtime-subcase-fields-invalid')
        if any(not isinstance(value, str) or value not in states for value in source.values()):
            raise ValueError('cross-version-runtime-subcase-verdict-invalid')
        output[name] = dict(sorted(source.items()))
    roles = ('candidate-sender', 'candidate-recipient')
    origin = ('siblingOrigin', 'wrongApp', 'expiredBrowserSession', 'staleProcessLaunchToken', 'decryptionSideEffects')
    selected('mailOrigin', runtime.get('mailOriginObservations'), [role + ':' + case for role in roles for case in origin])
    surfaces = ('appLogs', 'audit', 'support', 'queue', 'diagnostics')
    selected('mailCanary', runtime.get('mailCanaryObservations'), ['processLogs', 'collectorFailurePaths', 'privacy'] +
             [role + ':' + case for role in roles for case in surfaces])
    recovery = runtime.get('recoveryObservation')
    if recovery is not None:
        keys = ('daemonUpgrade', 'privateBackup', 'privateRestore', 'unsafeDowngrade', 'mailRestore', 'cleanup')
        selected('isolatedRecovery', {key: recovery[key] for key in keys}, keys)
    budget = runtime.get('budgetObservation')
    if budget is not None:
        selected('appBudget', budget.get('cases'), ('foreground-concurrency', 'foreground-rate',
                 'foreground-recovery', 'scheduler-queue-pressure-precedence'))
    catalog = runtime.get('catalogObservation')
    if catalog is not None:
        selected('catalog', catalog.get('outcomes'), ('signedCatalogAdmission', 'untrustedCatalogBlocking',
                 'exactMirrorSubject', 'sourceSwitchConsent', 'stableBetaIsolation', 'sameVersionDigestConflict',
                 'updatePermissionConsent', 'bundleRollback'))
    return output


def run(args):
    fresh_output(args.out_dir)
    migration = None
    if args.action == 'profile-compare':
        if not args.previous_source or not args.current_source:
            raise ValueError('cross-version-profile-source-required')
        result = adapter('cross_version_profiles').compare(
            args.workspace_root, args.previous_source, args.current_source)
        publish(args.out_dir, result)
        return 0
    plan = evidence.validate_plan(read(args.plan))
    if args.action == 'plan':
        result = {'schemaVersion': 1, 'kind': 'cryptad-cross-version-soak-preflight',
                  'planDigest': evidence.digest(plan), 'status': 'plan-validated',
                  'artifactAuthentication': 'not-performed', 'execution': 'not-executed',
                  'releaseEligible': False}
        if args.private_config:
            private = read(args.private_config, private=True)
            authorization = read(args.authorization, private=True) if args.authorization else None
            runtime = adapter('cross_version_runtime')
            try:
                runtime.preflight(plan, private, authorization)
            except runtime.RuntimeFailure:
                raise ValueError('cross-version-artifact-preflight-failed') from None
            result['artifactAuthentication'] = 'local-exact-byte-pins-checked'
        publish(args.out_dir, result)
        return 0
    if args.action == 'run':
        if not args.execute:
            raise ValueError('cross-version-explicit-execution-required')
        private = read(args.private_config, private=True)
        authorization = read(args.authorization, private=True)
        if args.journal_root is None or str(args.journal_root) != private.get('root'):
            raise ValueError('cross-version-journal-target-mismatch')
        public_root, private_root = args.out_dir.resolve(), args.journal_root.resolve()
        if public_root.is_relative_to(private_root) or private_root.is_relative_to(public_root):
            raise ValueError('cross-version-public-private-roots-overlap')
        continuation = read(args.continuation, private=True) if args.continuation else None
        runtime = adapter('cross_version_runtime')
        with evidence.Journal(args.journal_root, plan, continuation=continuation) as journal:
            if not journal.resumed:
                journal.append('start')
            try:
                runtime_result = runtime.run(plan, private, authorization, journal)
            except runtime.RuntimeFailure:
                raise ValueError('cross-version-runtime-admission-failed') from None
            if runtime_result.get('failureCode') == 'controller-interrupted':
                checkpoint = journal.checkpoint('partial')
            elif runtime_result.get('failureCode'):
                checkpoint = journal.checkpoint('failed')
            else:
                journal.append('finish')
                checkpoint = journal.checkpoint('complete')
            result = evidence.verify(plan, journal.events, checkpoint)
            result['supplementaryRuntimeSubcases'] = runtime_subcases(runtime_result)
            migration = runtime_result.get('migrationObservation')
            if migration is not None and migration.get('planDigest') != evidence.digest(plan):
                raise ValueError('cross-version-migration-plan-substituted')
    elif args.action in ('verify', 'closeout'):
        if args.journal_root is None:
            raise ValueError('cross-version-journal-required')
        checkpoint = read(args.journal_root / 'checkpoint.json', private=True)
        path = args.journal_root / 'journal.jsonl'
        if (path.is_symlink() or any(p.is_symlink() for p in path.parents)
                or not path.is_file() or path.stat().st_mode & 0o077
                or path.stat().st_uid != os.geteuid()
                or path.stat().st_size > plan['policy']['maxEvents'] * 2048):
            raise ValueError('cross-version-journal-input-invalid')
        events = []
        with path.open(encoding='utf-8') as stream:
            while True:
                if checkpoint['status'] == 'partial' and len(events) == checkpoint['sequence']:
                    break
                line = stream.readline(2049)
                if not line:
                    break
                if len(line) > 2048 or len(events) >= plan['policy']['maxEvents']:
                    raise ValueError('cross-version-journal-budget-exceeded')
                events.append(json.loads(line, object_pairs_hook=unique_members))
        result = evidence.verify(plan, events, checkpoint)
        if args.action == 'closeout':
            result['consumerProjection'] = 'blocked-original-protected-authority-required'
    else:
        raise ValueError('cross-version-action-required')
    publish(args.out_dir, result, migration=migration)
    return 0 if result['status'] == 'verified-local-integrity' else 2
