"""Real localhost HTTP tests of synthetic fixtures, never real LLMs or targets."""
import http.client
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
CONTROL = {"X-Fixture-Control": "local-synthetic-control"}


class WindowsFixtureJob:
    """Own only fixture PIDs; close/terminate kills this complete process tree."""
    def __init__(self, pids):
        # Win32 imports stay inside this Windows-only constructor.
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                        ("flags", wintypes.DWORD), ("min_working_set", ctypes.c_size_t),
                        ("max_working_set", ctypes.c_size_t), ("active_processes", wintypes.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("basic", BasicLimits), ("io", IoCounters), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel = kernel
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            limits = ExtendedLimits()
            limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise ctypes.WinError(ctypes.get_last_error())
            for pid in dict.fromkeys(pids):
                process_handle = kernel.OpenProcess(0x0101, False, pid)  # SET_QUOTA | TERMINATE
                if not process_handle:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    if not kernel.AssignProcessToJobObject(self.handle, process_handle):
                        raise ctypes.WinError(ctypes.get_last_error())
                finally:
                    kernel.CloseHandle(process_handle)
        except BaseException:
            self.close()
            raise

    def terminate(self):
        if self.handle and not self.kernel.TerminateJobObject(self.handle, 1):
            raise OSError("Failed to terminate the owned fixture job")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def node_runtime():
    candidates = [os.environ.get("VIBEAUDIT_TEST_NODE"), shutil.which("node"),
                  str(Path(sys.executable).resolve().parents[1] / "node" / "bin" / ("node.exe" if os.name == "nt" else "node")),
                  str(Path(getattr(sys, "_base_executable", sys.executable)).resolve().parents[1] / "node" / "bin" / ("node.exe" if os.name == "nt" else "node"))]
    for candidate in candidates:
        if not candidate or not Path(candidate).is_file():
            continue
        try:
            info = subprocess.run([candidate, "--version"], capture_output=True, text=True, timeout=5,
                                  creationflags=0x08000000 if os.name == "nt" else 0)
            if info.returncode == 0 and int(info.stdout.strip().lstrip("v").split(".")[0]) >= 24:
                return candidate
        except (ValueError, OSError, subprocess.TimeoutExpired):
            pass
    return None


class RunningFixture:
    """Own exactly one authored fixture process and always reap it on exit."""
    def __init__(self, argv):
        self.argv = argv
        self.process = None
        self.origin = None
        self.server_pid = None
        self.graceful_shutdown = False
        self.job = None

    def __enter__(self):
        self.process = subprocess.Popen(self.argv, cwd=str(FIXTURES), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        stdin=subprocess.DEVNULL, text=True,
                                        creationflags=0x08000000 if os.name == "nt" else 0)
        ready = queue.Queue()
        reader = threading.Thread(target=lambda: ready.put(self.process.stdout.readline()), daemon=True)
        reader.start()
        try:
            line = ready.get(timeout=8)
            data = json.loads(line)
            assert data["synthetic"] is True
            self.origin = data["origin"]
            self.server_pid = data["pid"]
            assert urlsplit(self.origin).hostname == "127.0.0.1"
            if os.name == "nt":
                # Startup JSON is emitted by our authored fixture. Register
                # both the actual interpreter and optional venv redirector.
                self.job = WindowsFixtureJob([self.server_pid, self.process.pid])
            return self
        except BaseException:
            self.stop()
            raise

    def request(self, method, path, *, token=None, payload=None, headers=None):
        parsed = urlsplit(self.origin)
        request_headers = dict(headers or {})
        if token:
            request_headers["Authorization"] = "Bearer " + token
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            request_headers["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=3)
        try:
            conn.request(method, path, body=body, headers=request_headers)
            response = conn.getresponse()
            raw = response.read(128 * 1024)
            return response.status, json.loads(raw)
        finally:
            conn.close()

    def stop(self):
        if not self.process:
            return
        # A Windows venv python.exe may be a redirector with an interpreter
        # child. Terminating only Popen.pid can orphan that listening child.
        # Ask the actual server to close itself before touching its launcher.
        if self.origin:
            try:
                status, response = self.request("POST", "/__fixture/shutdown", payload={}, headers=CONTROL)
                self.graceful_shutdown = status == 200 and response.get("shutting_down") is True
            except (OSError, http.client.HTTPException, ValueError):
                self.graceful_shutdown = False
        if self.process.poll() is None:
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    if self.job:
                        self.job.terminate()
                    else:
                        # Startup-failure fallback, before a PID report allowed
                        # job registration: target only the live Popen tree.
                        subprocess.run(["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=5, check=False, creationflags=0x08000000)
                else:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                self.process.wait(timeout=5)
        # poll() alone is not a replacement for reaping the process handle.
        self.process.wait(timeout=1)
        if self.job:
            self.job.close()
            self.job = None
        assert self.process.poll() is not None, "Fixture process remained alive"
        for stream in (self.process.stdout, self.process.stderr):
            if stream:
                stream.close()
        if self.origin:
            parsed = urlsplit(self.origin)
            # TerminateJobObject is asynchronous for child processes. Reaping
            # the venv launcher does not yet prove the child released its socket.
            deadline = time.monotonic() + 5
            while True:
                with socket.socket() as probe:
                    probe.settimeout(0.2)
                    if probe.connect_ex((parsed.hostname, parsed.port)) != 0:
                        break
                assert time.monotonic() < deadline, "Fixture still owns a listening port after shutdown"
                time.sleep(0.05)

    def __exit__(self, *_exc):
        self.stop()


class SyntheticFixtureHTTPTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows redirector process-tree fallback")
    def test_windows_fallback_reaps_redirector_tree_when_http_shutdown_unavailable(self):
        fixture = RunningFixture([sys.executable, str(FIXTURES / "ai-agent" / "server.py"), "--mode", "fixed", "--port", "0"])
        fixture.__enter__()
        try:
            self.assertEqual(fixture.request("GET", "/")[0], 200)
            with patch.object(fixture, "request", side_effect=OSError("Synthetic control transport failure")):
                fixture.stop()
            self.assertFalse(fixture.graceful_shutdown)
            self.assertIsNotNone(fixture.process.poll())
            # stop() retained the actual listening-port assertion after the
            # launcher and its interpreter child were terminated as one tree.
        finally:
            # Restore the real control endpoint for cleanup even if the
            # fallback assertion fails after a redirector has already exited.
            fixture.stop()

    def test_web_bola_and_logout_vulnerable_fixed(self):
        node = node_runtime()
        if not node:
            self.skipTest("Node.js >=24 unavailable; Web fixture runtime was not tested")
        for mode in ("vulnerable", "fixed"):
            with self.subTest(mode=mode), RunningFixture([node, str(FIXTURES / "web-api" / "server.ts"), "--mode", mode, "--port", "0"]) as fixture:
                status, positive = fixture.request("GET", "/orders/order-b", token="fixture-web-b")
                self.assertEqual(status, 200)
                self.assertEqual(positive["private_note"], "TENANT_B_ORDER_CANARY")
                status, own = fixture.request("GET", "/orders/order-a", token="fixture-web-a")
                self.assertEqual(status, 200)
                self.assertEqual(own["tenant_id"], "A")
                status, cross = fixture.request("GET", "/orders/order-b", token="fixture-web-a")
                self.assertEqual(status, 200 if mode == "vulnerable" else 403)
                self.assertEqual("TENANT_B_ORDER_CANARY" in json.dumps(cross), mode == "vulnerable")
                self.assertEqual(fixture.request("GET", "/me", token="fixture-web-a")[0], 200)
                self.assertEqual(fixture.request("POST", "/auth/logout", token="fixture-web-a", payload={})[0], 200)
                self.assertEqual(fixture.request("GET", "/me", token="fixture-web-a")[0], 200 if mode == "vulnerable" else 401)
                status, login = fixture.request("POST", "/auth/login", payload={"username": "alice", "password": "synthetic-alice"})
                self.assertEqual(status, 200)
                self.assertEqual(fixture.request("GET", "/me", token=login["token"])[0], 200)
                self.assertEqual(fixture.request("POST", "/__fixture/reset", headers=CONTROL, payload={})[0], 200)
                self.assertEqual(fixture.request("GET", "/me", token=login["token"])[0], 401)
                self.assertEqual(fixture.request("GET", "/me", token="fixture-web-a")[0], 200)
                self.assertEqual(fixture.request("GET", "/me", token="fixture-web-a", headers={"Host": "untrusted.invalid"})[0], 403)
                self.assertEqual(fixture.request("POST", "/auth/logout", token="fixture-web-a", payload={}, headers={"Origin": "https://untrusted.invalid"})[0], 403)
                self.assertEqual(fixture.request("POST", "/__fixture/shutdown", payload={})[0], 403)
            self.assertTrue(fixture.graceful_shutdown, "Web fixture did not use its graceful shutdown path")

    def test_mock_ai_retrieval_tool_effects_and_session_reset(self):
        for mode in ("vulnerable", "fixed"):
            with self.subTest(mode=mode), RunningFixture([sys.executable, str(FIXTURES / "ai-agent" / "server.py"), "--mode", mode, "--port", "0"]) as fixture:
                status, own = fixture.request("POST", "/retrieve", token="fixture-ai-a", payload={"document_id": "doc-a"})
                self.assertEqual(status, 200)
                self.assertEqual(own["documents"][0]["text"], "TENANT_A_RAG_CANARY")
                status, positive = fixture.request("GET", "/documents/doc-b", token="fixture-ai-b")
                self.assertEqual(status, 200)
                self.assertEqual(positive["documents"][0]["text"], "TENANT_B_RAG_CANARY")
                status, cross = fixture.request("POST", "/retrieve", token="fixture-ai-a", payload={"document_id": "doc-b"})
                self.assertEqual(status, 200 if mode == "vulnerable" else 403)
                self.assertEqual("TENANT_B_RAG_CANARY" in json.dumps(cross), mode == "vulnerable")
                status, proposed = fixture.request("POST", "/agent/run", token="fixture-ai-a", payload={"document_id": "doc-a-untrusted"})
                self.assertEqual(status, 200)
                self.assertEqual(proposed["model"], "deterministic-mock-no-llm")
                status, ledger = fixture.request("GET", "/__fixture/state?run_id=" + proposed["run_id"], headers=CONTROL)
                self.assertEqual(status, 200)
                phases = [event["phase"] for event in ledger["events"]]
                self.assertEqual(phases, ["retrieved", "proposed", "invoked", "committed"] if mode == "vulnerable" else ["retrieved", "proposed", "denied"])
                self.assertEqual(ledger["unauthorized_commits"], 1 if mode == "vulnerable" else 0)
                self.assertEqual(len(ledger["sink"]), 1 if mode == "vulnerable" else 0)
                self.assertTrue(ledger["trace_complete"])
                if ledger["sink"]:
                    self.assertEqual(ledger["sink"][0]["sink_kind"], "in_memory_mock")
                    self.assertFalse(ledger["sink"][0]["authorized"])
                status, authorized = fixture.request("POST", "/agent/run", token="fixture-ai-a", payload={"document_id": "doc-a", "action": "export", "approved": True})
                self.assertEqual(status, 200)
                _, normal = fixture.request("GET", "/__fixture/state?run_id=" + authorized["run_id"], headers=CONTROL)
                self.assertEqual(len(normal["sink"]), 1)
                self.assertTrue(normal["sink"][0]["authorized"])
                self.assertEqual(normal["unauthorized_commits"], 0)
                status, reset = fixture.request("POST", "/sessions/reset", token="fixture-ai-a", payload={})
                self.assertEqual(status, 200)
                self.assertEqual(reset["memory_size"], 0)
                _, state = fixture.request("GET", "/__fixture/state", headers=CONTROL)
                self.assertEqual(state["session_memory_sizes"]["A"], 0)
                self.assertGreater(len(state["sink"]), 0, "Session reset must not erase audit evidence")
                self.assertEqual(fixture.request("POST", "/__fixture/reset", headers=CONTROL, payload={})[0], 200)
                _, cleared = fixture.request("GET", "/__fixture/state", headers=CONTROL)
                self.assertEqual(cleared["events"], [])
                self.assertEqual(cleared["sink"], [])
                self.assertEqual(fixture.request("GET", "/documents/doc-a", token="fixture-ai-a", headers={"Host": "untrusted.invalid"})[0], 403)
                self.assertEqual(fixture.request("POST", "/__fixture/shutdown", payload={})[0], 403)
            self.assertTrue(fixture.graceful_shutdown, "AI fixture did not use its graceful shutdown path")


if __name__ == "__main__":
    unittest.main()
