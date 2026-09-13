"""Bounded cgroup v2 reads for the actual resource-observation process."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cross_version_runtime as runtime

with runtime.fixed_helper_imports():
    import scheduler_pressure_runtime as scheduler


class SchedulerEnvironmentTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.proc = self.root / 'proc'
        self.process = self.proc / '123'
        self.process.mkdir(parents=True)
        self.mount = self.root / 'cgroup'
        self.mount.mkdir()
        (self.mount / 'cgroup.controllers').write_text('cpu memory cpuset')
        (self.mount / 'cgroup.subtree_control').write_text('cpu memory')
        (self.process / 'cgroup').write_text('0::/\n')
        (self.process / 'mountinfo').write_text(f'7 6 0:25 / {self.mount} rw - cgroup2 none rw\n')
        (self.process / 'status').write_text('Cpus_allowed_list:\t0-3\n')
        (self.proc / 'meminfo').write_text('MemTotal: 8192 kB\n')
        self.identity = lambda pid: {'pid': pid, 'startTicks': 10}

    def observe(self):
        return scheduler.cgroup_environment(123, self.proc, self.identity)

    def child(self, name):
        path = self.mount / name
        path.mkdir(parents=True)
        (path / 'cgroup.subtree_control').write_text('cpu memory')
        (path / 'memory.max').write_text('max')
        (path / 'cpu.max').write_text('max 100000')
        return path

    def test_host_root_absent_nonroot_controller_files_are_known_unlimited(self):
        result = self.observe()
        self.assertTrue(result['known'])
        self.assertIsNone(result['memoryMax'])
        self.assertIsNone(result['cpuMax'])
        self.assertEqual(8388608, result['hostRamBytes'])
        self.assertEqual('0-3', result['processAllowedCpuList'])

    def test_inherited_limits_use_smallest_quota_ratio_and_memory_limit(self):
        parent = self.child('parent')
        leaf = self.child('parent/leaf')
        (self.process / 'cgroup').write_text('0::/parent/leaf')
        (parent / 'memory.max').write_text('1048576')
        (leaf / 'memory.max').write_text('2097152')
        (parent / 'cpu.max').write_text('100000 200000')
        (leaf / 'cpu.max').write_text('100000 100000')
        result = self.observe()
        self.assertTrue(result['known'])
        self.assertEqual(1048576, result['memoryMax'])
        self.assertEqual({'quotaMicros': 100000, 'periodMicros': 200000}, result['cpuMax'])
        self.assertEqual(3, result['ancestorCount'])

    def test_delegated_visible_root_finite_limits_are_included(self):
        (self.mount / 'memory.max').write_text('4194304')
        (self.mount / 'cpu.max').write_text('200000 100000')
        self.assertEqual(4194304, self.observe()['memoryMax'])

    def test_nonbinding_ancestor_quota_change_still_changes_configuration_fingerprint(self):
        leaf = self.child('leaf')
        (self.process / 'cgroup').write_text('0::/leaf')
        (leaf / 'cpu.max').write_text('50000 100000')
        (self.mount / 'cpu.max').write_text('200000 100000')
        before = self.observe()
        (self.mount / 'cpu.max').write_text('300000 100000')
        after = self.observe()
        self.assertEqual(before['cpuMax'], after['cpuMax'])
        self.assertNotEqual(before['controllerConfigurationDigest'],
                            after['controllerConfigurationDigest'])

    def test_missing_nonroot_limit_is_unavailable_not_unlimited(self):
        leaf = self.child('leaf')
        (self.process / 'cgroup').write_text('0::/leaf')
        (leaf / 'memory.max').unlink()
        self.assertFalse(self.observe()['known'])

    def test_unreadable_root_limit_is_unavailable_not_unlimited(self):
        original = scheduler._environment_text
        def read(path, maximum=4096):
            if path.name == 'memory.max':
                raise PermissionError('private detail')
            return original(path, maximum)
        with patch.object(scheduler, '_environment_text', side_effect=read):
            result = self.observe()
        self.assertFalse(result['known'])
        self.assertNotIn('private detail', str(result))

    def test_hidden_ancestors_and_v1_are_explicitly_unsupported(self):
        (self.process / 'mountinfo').write_text(f'7 6 0:25 /hidden {self.mount} rw - cgroup2 none rw')
        self.assertEqual('scheduler-cgroup-ancestors-unavailable', self.observe()['diagnostic'])
        (self.process / 'cgroup').write_text('4:memory:/leaf\n3:cpu:/leaf')
        self.assertEqual('scheduler-cgroup-v2-unsupported', self.observe()['diagnostic'])

    def test_traversal_and_symlinked_memberships_are_unavailable(self):
        (self.process / 'cgroup').write_text('0::/../outside')
        self.assertFalse(self.observe()['known'])
        (self.mount / 'alias').symlink_to(self.root, target_is_directory=True)
        (self.process / 'cgroup').write_text('0::/alias')
        self.assertFalse(self.observe()['known'])

    def test_membership_or_process_epoch_change_invalidates_observation(self):
        identities = iter([{'pid': 123, 'startTicks': 10}, {'pid': 123, 'startTicks': 11}])
        self.identity = lambda pid: next(identities)
        self.assertFalse(self.observe()['known'])
        self.identity = lambda pid: {'pid': pid, 'startTicks': 10}
        original = scheduler._environment_text
        reads = 0
        def read(path, maximum=4096):
            nonlocal reads
            if path.name == 'cgroup':
                reads += 1
                if reads > 1:
                    return '0::/changed'
            return original(path, maximum)
        with patch.object(scheduler, '_environment_text', side_effect=read):
            self.assertFalse(self.observe()['known'])

    def test_invalid_units_counts_masks_and_bounded_inputs_are_unavailable(self):
        for content in ['-1', 'NaN', str(2**63), '12 MB']:
            with self.subTest(memory=content):
                (self.mount / 'memory.max').write_text(content)
                self.assertFalse(self.observe()['known'])
        (self.mount / 'memory.max').unlink()
        (self.process / 'status').write_text('Cpus_allowed_list: 0-3,2')
        self.assertFalse(self.observe()['known'])
        (self.process / 'cgroup').write_text('0::/' + 'a' * 4096)
        self.assertFalse(self.observe()['known'])

    def test_ambiguous_mounts_and_ancestor_budget_are_unavailable(self):
        original = (self.process / 'mountinfo').read_text()
        (self.process / 'mountinfo').write_text(original + original)
        self.assertFalse(self.observe()['known'])
        (self.process / 'mountinfo').write_text(original)
        name = '/'.join(['nested'] * 33)
        self.child(name)
        (self.process / 'cgroup').write_text('0::/' + name)
        self.assertFalse(self.observe()['known'])

    def test_disabled_child_controller_has_no_direct_limit_but_inherits_ancestors(self):
        leaf = self.child('leaf')
        (self.process / 'cgroup').write_text('0::/leaf')
        (self.mount / 'cgroup.subtree_control').write_text('memory')
        (self.mount / 'cpu.max').write_text('50000 100000')
        (leaf / 'cpu.max').unlink()
        result = self.observe()
        self.assertTrue(result['known'])
        self.assertEqual({'quotaMicros': 50000, 'periodMicros': 100000}, result['cpuMax'])

    def test_wrong_selected_process_identity_is_unavailable(self):
        result = scheduler.cgroup_environment(123, self.proc, self.identity,
            expected_identity={'pid': 123, 'startTicks': 99})
        self.assertFalse(result['known'])
