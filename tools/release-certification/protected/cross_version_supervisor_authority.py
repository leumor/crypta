#!/usr/bin/env python3
"""Fixed protected control of the installed disposable supervisor.

A completed attested authorization job precedes start. Start reauthenticates that original
artifact before writing a root-owned activation record and starting one fixed systemd unit.
The service reads this OS-protected record inside its cgroup without retaining GitHub tokens.
This authorizes measured nonrelease experiments; it does not establish post-freeze eligibility.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
try:
    import pwd
except ImportError:  # Pure certification suite remains importable on Windows.
    pwd = None
import re
import subprocess
import stat
import sys
import tempfile
import time
import zipfile

CHECKOUT = Path('/opt/cryptad-cross-version/current')
STATE = Path('/var/lib/cryptad-cross-version')
AUTHORITY = Path('/var/lib/cryptad-cross-version-authority')
CONFIG = Path('/etc/cryptad-certification')
UNIT = 'cryptad-cross-version-soak.service'
WORKFLOW = '.github/workflows/cross-version-live-network-soak.yml'
_SEAL = object()

# Isolated Python invocation deliberately imports only the installed reviewed helper trees.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
from original_artifact_authentication import authenticate_original, _environment, _gh
from cryptad_certification.cross_version_evidence import digest, validate_plan, verify
from cryptad_certification.redaction import scan_value


class AuthorityError(ValueError):
    """Public diagnostic with no supplied text, paths, or credentials."""


def file_digest(path):
    with path.open('rb') as stream:
        return 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()


def secured(path, *, owner=0, private=False):
    if (path.is_symlink() or not path.is_file() or path.stat().st_uid != owner
            or path.stat().st_mode & (0o077 if private else 0o022)
            or any(p.is_symlink() or p.stat().st_mode & 0o022 or p.stat().st_uid != 0 for p in path.parents)):
        raise AuthorityError('protected-installed-file-not-confined')
    return path


def decode_json(payload):
    if len(payload) > 4 * 1024 * 1024:
        raise AuthorityError('protected-control-input-too-large')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AuthorityError('protected-control-duplicate-member')
            result[key] = value
        return result
    return json.loads(payload, object_pairs_hook=pairs)


def read_json(path):
    if path.stat().st_size > 4 * 1024 * 1024:
        raise AuthorityError('protected-control-input-too-large')
    return decode_json(path.read_bytes())


def directory_fd(path):
    """Anchor every absolute directory component without following replaceable symlinks."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise AuthorityError('protected-directory-must-be-absolute')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def bounded_fd(descriptor, maximum):
    payload = bytearray()
    while len(payload) <= maximum:
        block = os.read(descriptor, min(65536, maximum + 1 - len(payload)))
        if not block:
            break
        payload.extend(block)
    if len(payload) > maximum:
        raise AuthorityError('protected-control-input-too-large')
    return bytes(payload)


def read_selected(state, uid):
    """Read unprivileged configuration once through confined directory and file descriptors."""
    state_fd = directory_fd(state)
    selected_fd = None
    try:
        selected_fd = os.open('selected', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state_fd)
        for descriptor in (state_fd, selected_fd):
            observed = os.fstat(descriptor)
            if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != uid or observed.st_mode & 0o077:
                raise AuthorityError('protected-selected-root-not-private')
        values, hashes = {}, {}
        for name in ('plan', 'private-config', 'authorization', 'service-selection'):
            descriptor = os.open(name + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=selected_fd)
            try:
                observed = os.fstat(descriptor)
                if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != uid
                        or observed.st_mode & 0o077 or observed.st_nlink != 1
                        or observed.st_size > 4 * 1024 * 1024):
                    raise AuthorityError('protected-selected-input-not-private')
                payload = bounded_fd(descriptor, 4 * 1024 * 1024)
                values[name] = decode_json(payload)
                hashes[name] = 'sha256:' + hashlib.sha256(payload).hexdigest()
            finally:
                os.close(descriptor)
        return values, hashes
    finally:
        if selected_fd is not None:
            os.close(selected_fd)
        os.close(state_fd)


def installed_identity():
    # Root ownership includes the entire executable tree, not just a status version response.
    for directory, directories, files in os.walk(CHECKOUT, followlinks=False):
        path = Path(directory)
        if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
            raise AuthorityError('protected-checkout-not-root-owned')
        if any((path / name).is_symlink() for name in directories):
            raise AuthorityError('protected-checkout-directory-link')
        for name in files:
            secured(path / name)
    checked = subprocess.run(['/usr/bin/git', 'status', '--porcelain', '--untracked-files=normal'],
                             cwd=CHECKOUT, capture_output=True, timeout=30, check=True,
                             env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    if checked.stdout:
        raise AuthorityError('protected-installed-checkout-not-exact-clean-source')
    sys.path.insert(0, str(CHECKOUT / 'tools/interop'))
    from cross_version_runtime import implementation_identity
    return implementation_identity()


def selected_inputs():
    uid = pwd.getpwnam('cryptad-soak').pw_uid
    if any(parent.is_symlink() for parent in STATE.parents):
        raise AuthorityError('protected-selected-root-not-private')
    values, hashes = read_selected(STATE, uid)
    plan = validate_plan(values['plan'])
    if plan['profile'] != 'protected-long-live':
        raise AuthorityError('protected-selected-profile-invalid')
    identifier = plan['experimentId']
    root = STATE / 'experiments' / identifier
    private, authorization = values['private-config'], values['authorization']
    if private.get('root') != str(root) or authorization.get('root') != str(root):
        raise AuthorityError('protected-selected-root-mismatch')
    if (authorization.get('planDigest') != digest(plan)
            or authorization.get('experimentId') != identifier
            or authorization.get('syntheticContent') is not True
            or type(authorization.get('maxSeconds')) is not int
            or not plan['requestedSeconds'] <= authorization['maxSeconds'] <= 432000
            or type(authorization.get('maxOperations')) is not int
            or not 1 <= authorization['maxOperations'] <= 1000000):
        raise AuthorityError('protected-authorization-bounds-invalid')
    identity = installed_identity()
    if plan['producer'] != identity:
        raise AuthorityError('protected-installed-producer-mismatch')
    selection = values['service-selection']
    bindings = {'serviceDigest': file_digest(CHECKOUT / 'tools/interop/cross_version_service.py'),
                'planDigest': hashes['plan'],
                'privateConfigDigest': hashes['private-config'],
                'authorizationDigest': hashes['authorization']}
    if selection != {'schemaVersion': 1, **bindings}:
        raise AuthorityError('protected-service-selection-mismatch')
    return plan, private, authorization, uid, bindings


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def owned_cgroup():
    return any(line.endswith(':/system.slice/' + UNIT) for line in Path('/proc/self/cgroup').read_text().splitlines())


def run_identity():
    value = {name: os.environ.get(key) for name, key in (
        ('sourceCommit', 'GITHUB_SHA'), ('runId', 'GITHUB_RUN_ID'), ('runAttempt', 'GITHUB_RUN_ATTEMPT'))}
    if not re.fullmatch('[0-9a-f]{40}', value['sourceCommit'] or '') or any(
            not re.fullmatch('[1-9][0-9]{0,15}', value[key] or '') for key in ('runId', 'runAttempt')):
        raise AuthorityError('protected-current-job-identity-missing')
    return {'sourceCommit': value['sourceCommit'], 'runId': int(value['runId']), 'runAttempt': int(value['runAttempt'])}


def validate_report(report):
    common = {'schemaVersion', 'kind', 'operation', 'experimentId', 'planDigest', 'producer',
              'job', 'purpose', 'releaseEligible', 'selectionDigest'}
    variants = {
        'authorize': {'approvedBounds', 'plan', 'serviceDigest'},
        'start': {'previousReportDigest', 'previousOrigin', 'serviceState', 'approvalOrigin', 'approvalReportDigest'},
        'checkpoint': {'previousReportDigest', 'previousOrigin', 'serviceState', 'approvalOrigin', 'approvalReportDigest', 'checkpoint', 'observation'},
        'finish': {'previousReportDigest', 'previousOrigin', 'serviceState', 'approvalOrigin', 'approvalReportDigest', 'checkpoint', 'observation'},
    }
    version = report.get('schemaVersion') if isinstance(report, dict) else None
    extra = {'maintenanceMeasurements'} if version == 2 else set()
    if version in {3, 4}:
        extra = {'admittedProductsDigest'}
        if report.get('operation') in {'checkpoint', 'finish'}:
            extra.add('maintenanceMeasurements')
    if (not isinstance(report, dict) or report.get('operation') not in variants
            or set(report) != common | variants[report['operation']] | extra
            or type(version) is not int or version not in {1, 2, 3, 4} or (version == 2 and report['operation'] not in {'checkpoint', 'finish'})
            or (version in {3, 4} and report['operation'] not in {'start', 'checkpoint', 'finish'})
            or report.get('kind') != 'cryptad-cross-version-supervisor'
            or report.get('purpose') != 'nonrelease-observed-experiment' or report.get('releaseEligible') is not False):
        raise AuthorityError('protected-supervisor-report-contract-invalid')
    if version in {3, 4} and not re.fullmatch(r'sha256:[0-9a-f]{64}', str(report['admittedProductsDigest'])):
        raise AuthorityError('protected-supervisor-products-binding-invalid')
    if version in {2, 3, 4} and report['operation'] in {'checkpoint', 'finish'}:
        from maintenance_runtime_projection import validate
        measured = validate(report['maintenanceMeasurements'])
        if (measured['planDigest'] != report['planDigest'] or measured['producer'] != report['producer']
                or measured['checkpointDigest'] != report['checkpoint']['digest']
                or measured['schemaVersion'] != version - 1
                or (version in {3, 4} and measured['admittedProductsDigest'] != report['admittedProductsDigest'])):
            raise AuthorityError('protected-supervisor-measurements-binding-invalid')
    if report['operation'] == 'authorize':
        plan = validate_plan(report['plan'])
        if digest(plan) != report['planDigest'] or plan['producer'] != report['producer']:
            raise AuthorityError('protected-supervisor-authorize-plan-mismatch')
    return report


def authenticate_report(coordinates, private_root):
    if coordinates.get('sourceFamily') != 'cross-version-supervisor':
        raise AuthorityError('protected-supervisor-origin-family-mismatch')
    original = authenticate_original(coordinates, private_root)
    expected_name = f"cross-version-supervisor-{coordinates['runId']}-{coordinates['runAttempt']}"
    if coordinates.get('artifactName') != expected_name:
        raise AuthorityError('protected-supervisor-artifact-name-mismatch')
    with zipfile.ZipFile(io.BytesIO(original.content)) as archive:
        entries = archive.infolist()
        if len(entries) != 1 or entries[0].filename != 'cross-version-supervisor.json' or entries[0].file_size > 4 * 1024 * 1024 or (entries[0].external_attr >> 16) & 0o170000 == 0o120000:
            raise AuthorityError('protected-supervisor-artifact-shape-invalid')
        payload = archive.read(entries[0])
    member = private_root / 'cross-version-supervisor.json'
    member.write_bytes(payload)
    invocation = f"https://github.com/crypta-network/cryptad/actions/runs/{coordinates['runId']}/attempts/{coordinates['runAttempt']}"
    results = _gh(['attestation', 'verify', str(member), '--repo', 'crypta-network/cryptad',
                   '--signer-workflow', 'crypta-network/cryptad/' + WORKFLOW,
                   '--source-digest', coordinates['sourceCommit'], '--signer-digest', coordinates['sourceCommit'], '--format', 'json'], _environment())
    if not isinstance(results, list) or not any(row.get('verificationResult', {}).get('signature', {}).get('certificate', {}).get('runInvocationURI') == invocation for row in results if isinstance(row, dict)):
        raise AuthorityError('protected-supervisor-attested-attempt-mismatch')
    report = read_json(member)
    if report.get('job') != {key: coordinates[key] for key in ('sourceCommit', 'runId', 'runAttempt')}:
        raise AuthorityError('protected-supervisor-report-original-job-mismatch')
    validate_report(report)
    return report, original.coordinates


def _atomic(path, value, mode=0o600):
    temporary = path.with_suffix('.pending')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def authority_directory():
    if not AUTHORITY.exists():
        AUTHORITY.mkdir(mode=0o755)
        AUTHORITY.chmod(0o755)
    if (AUTHORITY.stat().st_uid != 0 or AUTHORITY.stat().st_mode & 0o022
            or AUTHORITY.stat().st_mode & 0o005 != 0o005 or AUTHORITY.is_symlink()):
        raise AuthorityError('protected-activation-root-not-owned')


def stop_owned_service():
    subprocess.run(['/usr/bin/systemctl', 'stop', UNIT], check=True, timeout=210,
                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _service_state():
    completed = subprocess.run(['/usr/bin/systemctl', 'show', UNIT, '--property=ActiveState,SubState,MainPID,ControlGroup', '--no-pager'],
                               capture_output=True, text=True, timeout=20, check=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    values = dict(line.split('=', 1) for line in completed.stdout.splitlines() if '=' in line)
    active = values.get('ActiveState') == 'active'
    if active:
        pid = int(values.get('MainPID', '0'))
        if pid <= 1 or values.get('ControlGroup') != '/system.slice/' + UNIT:
            raise AuthorityError('protected-service-runtime-identity-mismatch')
        command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        expected = [b'/usr/bin/python3', str(CHECKOUT / 'tools/interop/cross_version_service.py').encode()]
        if command[:2] != expected or Path(f'/proc/{pid}').stat().st_uid != pwd.getpwnam('cryptad-soak').pw_uid:
            raise AuthorityError('protected-service-process-not-selected')
    return 'running' if active else 'stopped'


class AuthenticatedRunner:
    """In-process admission from the selected root-owned activation, never a JSON flag."""
    def __init__(self, seal, activation):
        if seal is not _SEAL:
            raise AuthorityError('protected-runner-object-not-produced')
        self._activation = json.loads(json.dumps(activation))

    def remaining_seconds(self):
        return max(0.0, (self._activation['deadlineMonotonicNs'] - time.monotonic_ns()) / 10**9)

    def product_admission(self, plan, private_config):
        if (self._activation.get('planDigest') != digest(plan)
                or self._activation.get('privateConfigDigest') != digest(private_config)):
            raise AuthorityError('protected-activated-products-selection-mismatch')
        rows = self._activation.get('products')
        if not isinstance(rows, list) or {row['role'] for row in rows} != {node['role'] for node in plan['nodes']}:
            raise AuthorityError('protected-original-products-not-activated')
        import cross_version_product_admission as products
        selected = {row['role']: {**row, 'path': Path(private_config['nodes'][row['role']]['archivePath'])} for row in rows}
        admitted = products.AuthenticatedProducts(products._SEAL, digest(plan), selected)
        admitted.bind(plan, private_config)
        admitted.bind_apps(plan)
        return admitted

    def public_identity(self):
        return {'activationDigest': digest(self._activation), 'approvalOrigin': self._activation['approvalOrigin'],
                'approvalReportDigest': self._activation['approvalReportDigest'],
                'producer': self._activation['producer'], 'purpose': 'nonrelease-observed-experiment',
                'postFreezeBinding': 'not-established'}


def authenticate_runner(plan, private_config, authorization):
    """Tokenless service admission; root control already checked the original GitHub authority."""
    activation = read_json(secured(AUTHORITY / 'activation.json'))
    if (activation.get('schemaVersion') != 1 or activation.get('planDigest') != digest(plan)
            or activation.get('privateConfigDigest') != digest(private_config)
            or activation.get('authorizationDigest') != digest(authorization)
            or activation.get('producer') != plan['producer']
            or activation.get('ownerUid') != os.getuid()
            or activation.get('bootId') != boot_id()
            or type(activation.get('deadlineMonotonicNs')) is not int
            or not activation.get('startedMonotonicNs', -1) <= time.monotonic_ns() <= activation['deadlineMonotonicNs']):
        raise AuthorityError('protected-activation-binding-or-lifetime-mismatch')
    if not owned_cgroup():
        raise AuthorityError('protected-activation-outside-owned-service')
    return AuthenticatedRunner(_SEAL, activation)


def snapshot(plan, root, previous=None, *, expected_uid=None, require_eof=False, activation=None):
    expected_uid = pwd.getpwnam('cryptad-soak').pw_uid if expected_uid is None else expected_uid
    maximum = plan['policy']['maxEvents']
    from cryptad_certification.cross_version_evidence import event_byte_limit
    line_limit = event_byte_limit(plan) if 'scheduler' in plan.get('workloadInputs', {}) else 2048
    root_fd = directory_fd(root)
    files = {}
    try:
        observed = os.fstat(root_fd)
        if observed.st_uid != expected_uid or observed.st_mode & 0o077:
            raise AuthorityError('protected-journal-path-not-owned')
        for name, bound in (('checkpoint.json', 2048), ('journal.jsonl', (16 * 1024 * 1024 if "scheduler" in plan.get("workloadInputs", {}) else maximum * 2048))):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
            files[name] = descriptor
            observed = os.fstat(descriptor)
            if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != expected_uid
                    or observed.st_mode & 0o077 or observed.st_nlink != 1):
                raise AuthorityError('protected-journal-path-not-owned')
            if observed.st_size > bound:
                raise AuthorityError('protected-checkpoint-byte-budget-exceeded')
        checkpoint = decode_json(bounded_fd(files['checkpoint.json'], 2048))
        sequence = checkpoint.get('sequence')
        if type(sequence) is not int or not 0 <= sequence <= maximum:
            raise AuthorityError('protected-checkpoint-sequence-budget-invalid')
        events = []
        with os.fdopen(files.pop('journal.jsonl'), 'rb') as stream:
            for _ in range(sequence):
                line = stream.readline(line_limit + 1)
                if not line or len(line) > line_limit or not line.endswith(b'\n'):
                    raise AuthorityError('protected-checkpoint-journal-incomplete')
                events.append(decode_json(line))
            if (require_eof or checkpoint.get('status') == 'complete') and stream.read(1):
                raise AuthorityError('protected-terminal-checkpoint-trailing-journal')
    finally:
        for descriptor in files.values():
            os.close(descriptor)
        os.close(root_fd)
    observation = verify(plan, events, checkpoint)
    structural = {'journal-lineage-invalid', 'checkpoint-substitution-or-truncation', 'continuation-lineage-invalid', 'runtime-epoch-mismatch', 'clock-discontinuity', 'journal-wall-clock-invalid'}
    if structural.intersection(observation['findings']):
        raise AuthorityError('protected-checkpoint-lineage-invalid')
    if previous and 'checkpoint' in previous:
        prior = previous['checkpoint']
        sequence = prior['sequence']
        if sequence > len(events) or (digest(events[sequence - 1]) if sequence else 'sha256:' + '0' * 64) != prior['tailDigest']:
            raise AuthorityError('protected-checkpoint-tail-substitution')
    result = {'checkpoint': {'sequence': checkpoint['sequence'], 'tailDigest': checkpoint['tailDigest'],
                            'digest': digest(checkpoint), 'status': checkpoint['status']}, 'observation': observation}
    if activation is not None:
        if activation.get('planDigest') != digest(plan) or activation.get('producer') != plan['producer']:
            raise AuthorityError('protected-measurements-activation-substituted')
        from maintenance_runtime_projection import project
        result['maintenanceMeasurements'] = project(plan, events, checkpoint, activation.get('products'))
    return result


def control(operation):
    if pwd is None or os.name != 'posix' or os.geteuid() != 0 or operation not in {'authorize', 'start', 'checkpoint', 'finish'}:
        raise AuthorityError('protected-control-fixed-root-operation-required')
    plan, private, authorization, uid, bindings = selected_inputs()
    job = run_identity()
    if job['sourceCommit'] != plan['producer']['sourceCommit']:
        raise AuthorityError('protected-workflow-installed-source-mismatch')
    report = {'schemaVersion': 1, 'kind': 'cryptad-cross-version-supervisor', 'operation': operation,
              'experimentId': plan['experimentId'], 'planDigest': digest(plan), 'producer': plan['producer'],
              'job': job, 'purpose': 'nonrelease-observed-experiment', 'releaseEligible': False}
    # These digests bind operational inputs but are intentionally private in the activation;
    # authorization exports only the exact public plan and executable/service identity.
    selection_binding = digest(bindings)
    report['selectionDigest'] = selection_binding
    if operation == 'authorize':
        if _service_state() != 'stopped' or Path(private['root']).exists():
            raise AuthorityError('protected-authorization-topology-not-new')
        report['approvedBounds'] = {key: authorization[key] for key in ('maxSeconds', 'maxOperations', 'syntheticContent')}
        report['plan'] = plan
        report['serviceDigest'] = bindings['serviceDigest']
        return report
    coordinates_path = CONFIG / ('cross-version-start.json' if operation == 'start' else 'cross-version-previous.json')
    coordinates = read_json(secured(coordinates_path, private=True))
    with tempfile.TemporaryDirectory(prefix='cryptad-supervisor-auth-') as directory:
        previous, origin = authenticate_report(coordinates, Path(directory))
    if any(previous.get(key) != report[key] for key in ('experimentId', 'planDigest', 'producer', 'selectionDigest')):
        raise AuthorityError('protected-original-authorization-selection-mismatch')
    report['previousReportDigest'] = digest(previous)
    report['previousOrigin'] = origin
    if operation == 'start':
        if previous.get('operation') != 'authorize' or previous.get('plan') != plan:
            raise AuthorityError('protected-start-requires-original-authorization')
        if _service_state() != 'stopped' or Path(private['root']).exists():
            raise AuthorityError('protected-start-topology-not-new')
        product_rows = None
        if plan['provenanceClass'] == 'production-artifact-comparison':
            import cross_version_product_admission as products
            with tempfile.TemporaryDirectory(prefix='cryptad-supervisor-products-') as directory:
                selected_products = products.authenticate_products(plan, private.get('productAdmission'), Path(directory) / 'original')
                selected_products.bind(plan, private)
                selected_products.bind_apps(plan)
                product_rows = selected_products.public_identities()
        authority_directory()
        used = AUTHORITY / ('used-' + str(origin['artifactId']) + '.json')
        if used.exists() or (AUTHORITY / 'activation.json').exists():
            raise AuthorityError('protected-start-reuse-requires-reconciliation')
        now = time.monotonic_ns()
        activation = {'schemaVersion': 1, 'planDigest': digest(plan), 'privateConfigDigest': digest(private),
                      'authorizationDigest': digest(authorization), 'producer': plan['producer'],
                      'approvalOrigin': origin, 'approvalReportDigest': digest(previous),
                      'ownerUid': uid, 'bootId': boot_id(),
                      'startedMonotonicNs': now, 'deadlineMonotonicNs': now + authorization['maxSeconds'] * 10**9,
                      'products': product_rows}
        _atomic(used, {'approvalOrigin': origin})
        _atomic(AUTHORITY / 'activation.json', activation, 0o644)
        subprocess.run(['/usr/bin/systemctl', 'start', UNIT], check=True, timeout=30,
                       env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        report['serviceState'] = _service_state()
        if report['serviceState'] != 'running':
            raise AuthorityError('protected-service-start-not-observed')
        report['approvalOrigin'] = origin
        report['approvalReportDigest'] = digest(previous)
        if product_rows and any('runtimeBinding' in row for row in product_rows):
            report['schemaVersion'] = 4 if 'scheduler' in plan.get('workloadInputs', {}) else 3
            report['admittedProductsDigest'] = digest(product_rows)
        return report
    if previous.get('operation') not in {'start', 'checkpoint'}:
        raise AuthorityError('protected-collection-requires-original-start-lineage')
    activation = read_json(secured(AUTHORITY / 'activation.json'))
    if activation.get('planDigest') != digest(plan) or activation.get('producer') != plan['producer']:
        raise AuthorityError('protected-collection-activation-mismatch')
    expected_origin = activation['approvalOrigin']
    if previous.get('approvalOrigin') != expected_origin:
        raise AuthorityError('protected-collection-original-start-substituted')
    if activation.get('products') and any('runtimeBinding' in row for row in activation['products']):
        bound_digest = digest(activation['products'])
        if previous.get('schemaVersion') != (4 if 'scheduler' in plan.get('workloadInputs', {}) else 3) or previous.get('admittedProductsDigest') != bound_digest:
            raise AuthorityError('protected-collection-products-substituted')
        # Reopen the admitted private files at every continuation/finish boundary. Root activation
        # is the authority; no release credential or online authentication is passed to the service.
        AuthenticatedRunner(_SEAL, activation).product_admission(plan, private)
        report['admittedProductsDigest'] = bound_digest
    report['approvalOrigin'] = expected_origin
    report['approvalReportDigest'] = activation['approvalReportDigest']
    report['serviceState'] = _service_state()
    if operation == 'finish' and report['serviceState'] != 'stopped':
        raise AuthorityError('protected-finish-service-still-running')
    report.update(snapshot(plan, Path(private['root']), previous, expected_uid=uid,
                           require_eof=operation == 'finish', activation=activation))
    report['schemaVersion'] = report['maintenanceMeasurements']['schemaVersion'] + 1
    return report


def main():
    previous_umask = os.umask(0o077)
    previous_path = os.environ.get('PATH')
    try:
        if len(sys.argv) != 2:
            raise AuthorityError('protected-operation-required')
        os.environ['PATH'] = '/usr/bin:/bin'
        result = control(sys.argv[1])
        # Constructed allowlist plus the shared fail-closed redaction gate.
        if scan_value(result):
            if result.get('operation') in {'start', 'checkpoint'} and result.get('serviceState') == 'running':
                stop_owned_service()
            raise AuthorityError('protected-supervisor-public-redaction-failed')
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile):
        print('protected-supervisor-control-failed-private-reconciliation-required', file=sys.stderr)
        return 2
    finally:
        os.umask(previous_umask)
        if previous_path is None:
            os.environ.pop('PATH', None)
        else:
            os.environ['PATH'] = previous_path


if __name__ == '__main__':
    raise SystemExit(main())
