"""Public-only transparency command; network observation is always explicit."""
from pathlib import Path
import json

from . import transparency_bundle as bundle
from . import transparency_sources as sources


def _package(args):
    if args.source_package:
        if args.selection or args.source_root or args.as_of:
            bundle.fail('source-package-options-conflict')
        package = sources.strict_json(sources.safe_read(args.source_package))
        sources.admit(package)
        if args.demo != (package['selection']['mode'] == 'demo'):
            bundle.fail('source-mode-mismatch')
        return package
    if args.selection:
        selected = sources.load_selection(args.selection)
        if args.demo != (selected['mode'] == 'demo'):
            bundle.fail('source-mode-mismatch')
        if args.as_of:
            selected = {**selected, 'asOf': args.as_of}
            sources.validate_selection(selected)
        return sources.collect(selected, args.source_root or args.selection.parent)
    if not args.as_of:
        bundle.fail('snapshot-time-required')
    selection = {'schemaVersion': 1, 'mode': 'demo' if args.demo else 'production',
                 'asOf': args.as_of, 'sources': []}
    if not args.demo:
        return sources.collect(selection, Path.cwd())
    from .transparency_adapters import demo_sources
    from .transparency_public_projection import demo_public_projections
    import base64
    members = []
    for number, item in enumerate(demo_sources() + demo_public_projections()):
        role, raw = item["role"], item["raw"]
        name = f'source-{number:02d}.json'
        selection['sources'].append({'role': role, 'file': name, 'digest': sources.digest(raw),
                                     'size': len(raw), 'required': True})
        members.append({'file': name, 'bytes': base64.b64encode(raw).decode('ascii')})
    _, pin = sources.policy()
    package = {'schemaVersion': 1, 'policyDigest': pin, 'selection': selection, 'members': members}
    sources.admit(package)
    return package


def run(args):
    try:
        if args.demo and args.production or args.online and args.mode not in ('collect', 'project'):
            bundle.fail('mode-options-conflict')
        if args.mode != 'checkpoint' and args.previous_manifest_digest and not args.previous_bundle:
            bundle.fail('checkpoint-bundle-required')
        if args.bootstrap_manifest_digest and args.mode != 'checkpoint':
            bundle.fail('bootstrap-mode-invalid')
        if args.mode == 'checkpoint':
            if not args.url or not args.output or args.demo:
                bundle.fail('checkpoint-input-required')
            result = bundle.collect_checkpoint(args.url, args.output,
                previous_manifest=args.previous_manifest_digest, bootstrap_manifest=args.bootstrap_manifest_digest)
        elif args.mode == 'plan':
            rules, pin = sources.policy()
            result = {'schemaVersion': 1, 'policyDigest': pin, 'roles': rules['roles'],
                      'productionSourceCount': len(rules['approvedSources']),
                      'publication': 'not-performed', 'activation': 'not-performed',
                      'network': 'not-performed'}
        elif args.mode == 'project':
            if args.demo:
                bundle.fail('project-demo-option-invalid')
            if not args.role or not args.authority_manifest or not args.private_root or not args.output:
                bundle.fail('private-authority-inputs-required')
            output = bundle.confined(args.output)
            private_root = bundle.confined(args.private_root)
            if output.exists() or not output.parent.is_dir() or output.is_relative_to(private_root):
                bundle.fail('public-output-must-be-fresh-and-separate')
            from .transparency_public_projection import export_from_manifest
            raw = export_from_manifest(args.role, args.authority_manifest, private_root, allow_network=args.online)
            with output.open('xb') as stream:
                stream.write(raw)
            result = {'status': 'source-owned-public-projection', 'digest': bundle.digest(raw),
                      'originalProducerProof': 'not-exported-private-context',
                      'publication': 'not-performed', 'activation': 'not-performed'}
        elif args.mode == 'build':
            if not args.output:
                bundle.fail('output-required')
            result = bundle.build(_package(args), args.output, previous=args.previous_bundle,
                                  previous_manifest=args.previous_manifest_digest)
        elif args.mode == 'collect':
            if not args.selection or not args.output:
                bundle.fail('selection-and-output-required')
            selected = sources.load_selection(args.selection)
            package = sources.collect_online(selected) if args.online else _package(args)
            output = bundle.confined(args.output)
            if output.exists() or not output.parent.is_dir():
                bundle.fail('output-must-be-fresh')
            raw = bundle.canonical(package)
            with output.open('xb') as stream:
                stream.write(raw)
            result = {'status': 'collected-public-sources', 'digest': bundle.digest(raw),
                      'publication': 'not-performed'}
        elif args.mode == 'verify':
            if not args.bundle:
                bundle.fail('bundle-required')
            result = bundle.verify(args.bundle, expected_manifest=args.expected_manifest_digest,
                                   production=args.production)
            if args.previous_bundle:
                prior = bundle.verify_checkpoint(args.previous_bundle, args.previous_manifest_digest) if args.previous_manifest_digest else bundle.verify(args.previous_bundle)['index']
                bundle.check_history(result['index'], prior)
            result.pop('index')
        elif args.mode == 'observe':
            if not args.bundle or not args.url or not args.observed_at or not args.expected_manifest_digest:
                bundle.fail('observation-input-required')
            result = bundle.observe(args.bundle, args.url, args.observed_at,
                                    expected_manifest=args.expected_manifest_digest)
        else:
            bundle.fail('mode-required')
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return 0 if result.get('status') not in ('conflict', 'unavailable', 'partial') else 2
    except Exception:
        # Only fixed diagnostics cross this boundary: no paths, raw exceptions or input snippets.
        print('{"status":"blocked","reason":"transparency-input-or-verification-failed"}')
        return 2
