"""Control-plane tests with an injected runner; these do NOT execute scanners."""
import asyncio
import json
import os
import shutil
import uuid
import unittest
from pathlib import Path
from unittest.mock import patch

from vibe_audit import sandbox


# Artificial digest used only to validate command composition in unit tests.
TEST_PINS = {name: repo + "@sha256:" + "a" * 64 for name, repo in sandbox._REPOSITORIES.items()}


class FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", code=0, done=True):
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stdout.feed_eof()
        self.stderr.feed_data(stderr)
        self.stderr.feed_eof()
        self.code = code
        self.done = asyncio.Event()
        self.waited = 0
        self.killed = False
        if done:
            self.done.set()

    async def wait(self):
        self.waited += 1
        await self.done.wait()
        return self.code

    def kill(self):
        self.killed = True
        self.code = -9
        self.done.set()


class FakeRunner:
    def __init__(self, *, stdout=b"[]", code=0, hang=False, fail_cleanup=False, cancel=None):
        self.output, self.code = stdout, code
        self.hang, self.fail_cleanup, self.cancel = hang, fail_cleanup, cancel
        self.calls = []
        self.process = None
        self.started = asyncio.Event()

    async def __call__(self, argv, *, env, cwd):
        self.calls.append({"argv": argv, "env": env, "cwd": cwd})
        verb = argv[3]
        if verb == "run":
            self.process = FakeProcess(self.output, code=self.code, done=not self.hang)
            self.started.set()
            if self.cancel:
                self.cancel.set()
            return self.process
        if verb == "kill" and not self.fail_cleanup:
            self.process.kill()
        return FakeProcess(code=1 if self.fail_cleanup else 0)

    def verbs(self):
        return [c["argv"][3] for c in self.calls]


class SandboxTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_root = Path(__file__).resolve().parents[3] / "work" / "adapter-tests"
        self.temp_root.mkdir(parents=True, exist_ok=True)
        self.temp_dir = self.temp_root / ("vibeaudit-tests-" + uuid.uuid4().hex)
        self.temp_dir.mkdir()
        self.source = self.temp_dir / "source"
        self.source.mkdir()
        (self.source / "app.py").write_text("print('synthetic fixture')\n", encoding="utf-8")
        self.cancel = asyncio.Event()
        self.leases = 0

    async def asyncTearDown(self):
        self.assertTrue(self.temp_dir.resolve().is_relative_to(self.temp_root.resolve()))
        shutil.rmtree(self.temp_dir)

    async def lease(self):
        self.leases += 1

    async def run_scan(self, runner, scanner="gitleaks", **kwargs):
        return await sandbox.run_scanner(scanner, str(self.source), image_pins=TEST_PINS,
                                         cancel_event=self.cancel, lease_hook=self.lease,
                                         process_runner=runner, **kwargs)

    def test_commands_pin_images_and_isolate_source(self):
        argv = sandbox.build_scanner_command("semgrep", str(self.source), image_pins=TEST_PINS,
                                             container_name="vibeaudit-" + "b" * 32)
        for flag, value in [("--network", "none"), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"),
                            ("--pull", "never"), ("--pids-limit", "128"), ("--memory", "512m"), ("--cpus", "1"), ("--user", "65534:65534")]:
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn("--read-only", argv)
        self.assertIn("--tmpfs", argv)
        self.assertIn(TEST_PINS["semgrep"], argv)
        mounts = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--mount"]
        self.assertTrue(all("readonly" in mount for mount in mounts))
        self.assertTrue(all("docker.sock" not in mount for mount in mounts))
        self.assertTrue(any("target=/src" in mount for mount in mounts))
        self.assertIn("--disable-nosem", argv)
        self.assertNotIn("--allow-local-builds", argv)
        self.assertNotIn("--privileged", argv)

    def test_tags_foreign_images_arbitrary_scanners_and_bad_names_rejected(self):
        for pins in [{"semgrep": "semgrep/semgrep:latest"}, {"semgrep": "evil/repo@sha256:" + "a" * 64}, {}]:
            with self.assertRaises(sandbox.SandboxBlocked):
                sandbox.build_scanner_command("semgrep", str(self.source), image_pins=pins, container_name="vibeaudit-" + "b" * 32)
        for tool, name in [("zap", "vibeaudit-" + "b" * 32), ("semgrep", "untrusted --privileged")]:
            with self.assertRaises(sandbox.SandboxBlocked):
                sandbox.build_scanner_command(tool, str(self.source), image_pins=TEST_PINS, container_name=name)

    def test_ignore_files_cannot_silently_hide_source(self):
        (self.source / ".semgrepignore").write_text("*", encoding="utf-8")
        with self.assertRaises(sandbox.SandboxBlocked):
            sandbox.build_scanner_command("semgrep", str(self.source), image_pins=TEST_PINS, container_name="vibeaudit-" + "b" * 32)

    def test_osv_offline_database_is_required_and_readonly(self):
        with self.assertRaises(sandbox.SandboxBlocked):
            sandbox.build_scanner_command("osv", str(self.source), image_pins=TEST_PINS, container_name="vibeaudit-" + "b" * 32)
        db = self.temp_dir / "db"
        (db / "osv-scanner" / "PyPI").mkdir(parents=True)
        (db / "osv-scanner" / "PyPI" / "all.zip").write_bytes(b"not-a-real-db-test-only")
        argv = sandbox.build_scanner_command("osv", str(self.source), image_pins=TEST_PINS,
                                             container_name="vibeaudit-" + "b" * 32, offline_db_dir=str(db))
        self.assertIn("--offline", argv)
        self.assertNotIn("--download-offline-databases", argv)
        self.assertIn("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db", argv)
        self.assertTrue(any("target=/db,readonly" in arg for arg in argv))

    async def test_success_reaps_container_and_imports_no_secret_fields(self):
        output = json.dumps([{"RuleID": "fixture-rule", "File": "/src/app.py", "StartLine": 3,
                              "Description": "Synthetic secret candidate", "Secret": "NEVER_RETURN_RAW_SECRET",
                              "Match": "source-line-with-secret"}]).encode()
        runner = FakeRunner(stdout=output, code=1)
        with patch.dict(os.environ, {"VIBEAUDIT_PRIVATE_KEY": "do-not-forward", "DOCKER_HOST": "tcp://evil.invalid:2375"}):
            result = await self.run_scan(runner)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["control_plane_test"])
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(runner.verbs(), ["run", "wait", "rm"])
        self.assertGreaterEqual(runner.process.waited, 2)
        self.assertEqual(result["findings"][0]["file"], "app.py")
        self.assertNotIn("NEVER_RETURN_RAW_SECRET", json.dumps(result))
        self.assertNotIn("source-line-with-secret", json.dumps(result))
        self.assertNotIn("VIBEAUDIT_PRIVATE_KEY", runner.calls[0]["env"])
        self.assertNotIn("DOCKER_HOST", runner.calls[0]["env"])

    async def test_semgrep_analysis_error_is_incomplete(self):
        runner = FakeRunner(stdout=json.dumps({"results": [], "errors": [{"message": "parse error"}], "paths": {"scanned": ["/src/app.py"]}}).encode())
        result = await self.run_scan(runner, scanner="semgrep")
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["gaps"])

    async def test_empty_garbage_or_failure_exit_does_not_pass(self):
        for stdout, code in [(b"", 0), (b"not JSON", 0), (b"[]", 2), (b"[]", 1)]:
            result = await self.run_scan(FakeRunner(stdout=stdout, code=code))
            self.assertEqual(result["status"], "execution_error")

    async def test_cancellation_kills_waits_removes_and_reaps(self):
        runner = FakeRunner(hang=True, cancel=self.cancel)
        result = await self.run_scan(runner)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(runner.verbs(), ["run", "kill", "wait", "rm"])
        self.assertTrue(runner.process.done.is_set())
        self.assertGreaterEqual(runner.process.waited, 1)

    async def test_async_task_cancellation_cleans_up(self):
        runner = FakeRunner(hang=True)
        task = asyncio.create_task(self.run_scan(runner))
        await runner.started.wait()
        task.cancel()
        result = await task
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(runner.verbs(), ["run", "kill", "wait", "rm"])
        self.assertTrue(result["cleanup_confirmed"])

    async def test_expired_lease_after_spawn_terminates_container(self):
        runner = FakeRunner(hang=True)
        async def expiring_lease():
            self.leases += 1
            if self.leases >= 2:
                raise RuntimeError("expired")
        result = await sandbox.run_scanner("gitleaks", str(self.source), image_pins=TEST_PINS, cancel_event=self.cancel,
                                           lease_hook=expiring_lease, process_runner=runner)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(runner.verbs(), ["run", "kill", "wait", "rm"])

    async def test_expired_lease_before_spawn_has_no_process(self):
        runner = FakeRunner()
        async def expired():
            raise RuntimeError("expired-secret")
        result = await sandbox.run_scanner("gitleaks", str(self.source), image_pins=TEST_PINS, cancel_event=self.cancel,
                                           lease_hook=expired, process_runner=runner)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(runner.calls, [])
        self.assertNotIn("expired-secret", json.dumps(result))

    async def test_timeout_and_output_limit_terminate_not_pass(self):
        for runner in [FakeRunner(hang=True), FakeRunner(stdout=b"x" * 100, hang=True)]:
            with patch.object(sandbox, "MAX_OUTPUT_BYTES", 32):
                result = await self.run_scan(runner, timeout_seconds=0.06)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(runner.verbs(), ["run", "kill", "wait", "rm"])
            self.assertNotIn("stdout", result)

    async def test_unconfirmed_cleanup_is_outcome_unknown(self):
        runner = FakeRunner(hang=True, fail_cleanup=True, cancel=self.cancel)
        result = await self.run_scan(runner)
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertFalse(result["cleanup_confirmed"])
        self.assertTrue(runner.process.killed)
        self.assertGreaterEqual(runner.process.waited, 1)

    async def test_no_docker_blocks_without_host_fallback(self):
        with patch.object(sandbox.shutil, "which", return_value=None):
            result = await sandbox.run_scanner("gitleaks", str(self.source), image_pins=TEST_PINS, cancel_event=self.cancel, lease_hook=self.lease)
            capability = sandbox.sandbox_capabilities(TEST_PINS)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(all(not c["available"] and not c["integration_verified"] for c in capability))


if __name__ == "__main__":
    unittest.main()
