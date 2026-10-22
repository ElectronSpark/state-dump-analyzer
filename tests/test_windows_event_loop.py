from __future__ import annotations

import asyncio
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import Mock, patch

from router_dump_analyzer import windows_event_loop
from router_dump_analyzer.cli import _run_uvicorn

# Public, disposable loopback-test identity. Never used by the application.
_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIBSjCB8aADAgECAhQ8Sb1lDHP5Iz1Cd/Te3C9/OcO/PjAKBggqhkjOPQQDAjAU
MRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYxMDIyMjEzNzU1WhcNMzYxMDE5MjEz
NzU1WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAATzQxMy9iQWjvu8tyY1e1sOnJV741PoRfwEOuEqc+El5ahiSq7IIBXEtNHW
mPapsYb6kuTor6DQMn9l+LLI4GDyoyEwHzAdBgNVHQ4EFgQUgxrueLR/cNf190Ow
gbzGO1ickcswCgYIKoZIzj0EAwIDSAAwRQIhAJv6eYgr7DHZwW26XQbVsjReGutV
ppcP88JDKno1V3l0AiBw40lpBlgghElCO+H7d377GRgHrlYDYNpocVR3Yt2L3w==
-----END CERTIFICATE-----
"""
_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcWq93VaTQavW9DJ6
Q3HIGvCQg/yMk0xGOjFW9tx62XOhRANCAATzQxMy9iQWjvu8tyY1e1sOnJV741Po
RfwEOuEqc+El5ahiSq7IIBXEtNHWmPapsYb6kuTor6DQMn9l+LLI4GDy
-----END PRIVATE KEY-----
"""


class WindowsSocketOwnershipTests(unittest.TestCase):
    def test_adaptation_preserves_socket_identity_descriptor_and_timeout(self) -> None:
        original = socket.socket()
        original.settimeout(2.5)
        descriptor = original.fileno()
        owned = windows_event_loop._reset_safe_socket(original)
        try:
            self.assertIs(owned, original)
            self.assertEqual(owned.fileno(), descriptor)
            self.assertEqual(owned.gettimeout(), 2.5)
            self.assertIs(windows_event_loop._reset_safe_socket(owned), owned)
        finally:
            owned.close()
        self.assertEqual(owned.fileno(), -1)

    def test_custom_socket_is_rejected_without_changing_its_ownership(self) -> None:
        class CustomSocket(socket.socket):
            pass

        with CustomSocket() as original:
            descriptor = original.fileno()
            with self.assertRaisesRegex(TypeError, "plain socket"):
                windows_event_loop._reset_safe_socket(original)
            self.assertIs(type(original), CustomSocket)
            self.assertEqual(original.fileno(), descriptor)

    def test_closed_socket_does_not_create_a_new_descriptor(self) -> None:
        original = socket.socket()
        original.close()
        with self.assertRaisesRegex(ValueError, "closed socket"):
                windows_event_loop._reset_safe_socket(original)

    def test_only_full_shutdown_connection_reset_is_tolerated(self) -> None:
        with windows_event_loop._ResetSafeSocket() as owned:
            for how in (socket.SHUT_RD, socket.SHUT_WR, socket.SHUT_RDWR):
                for error in (ConnectionResetError(10054, "reset"), OSError(123, "unrelated")):
                    with (
                        self.subTest(how=how, error=type(error).__name__),
                        patch.object(socket.socket, "shutdown", side_effect=error),
                    ):
                        if how == socket.SHUT_RDWR and type(error) is ConnectionResetError:
                            owned.shutdown(how)
                        else:
                            with self.assertRaises(type(error)) as caught:
                                owned.shutdown(how)
                            self.assertIs(caught.exception, error)

    def test_non_windows_factory_rejects_without_global_policy_mutation(self) -> None:
        policy = asyncio.get_event_loop_policy()
        with (
            patch.object(windows_event_loop.sys, "platform", "linux"),
            self.assertRaisesRegex(RuntimeError, "requires Windows"),
        ):
            windows_event_loop.new_event_loop()
        self.assertIs(asyncio.get_event_loop_policy(), policy)


@unittest.skipUnless(sys.platform == "win32", "requires Windows IOCP")
class WindowsServerLoopTests(unittest.TestCase):
    def test_both_uvicorn_generations_select_the_local_windows_factory(self) -> None:
        from tests.test_uvicorn_compatibility import _application, _fake_uvicorn

        for generation in ("legacy", "modern"):
            with self.subTest(generation=generation):
                events = []
                uvicorn = _fake_uvicorn(events, api_generation=generation)
                with (
                    patch.dict(sys.modules, {"uvicorn": uvicorn}),
                    patch.object(windows_event_loop, "new_event_loop", wraps=windows_event_loop.new_event_loop) as factory,
                ):
                    _run_uvicorn(_application(events), host="127.0.0.1", port=8765)
                factory.assert_called_once_with()
                self.assertEqual(events[-3:], ["lifespan.enter", "serve", "lifespan.exit"])

    def test_injected_reset_finishes_original_transport_cleanup_exactly_once(self) -> None:
        from asyncio.proactor_events import _ProactorBasePipeTransport

        for protocol_error in (None, ValueError("protocol failure")):
            with self.subTest(protocol_error=protocol_error):
                owned = windows_event_loop._ResetSafeSocket()
                transport = object.__new__(_ProactorBasePipeTransport)
                transport._called_connection_lost = False
                protocol = transport._protocol = Mock()
                server = transport._server = Mock()
                transport._sock = owned
                if protocol_error:
                    protocol.connection_lost.side_effect = protocol_error
                with (
                    patch.object(socket.socket, "shutdown", side_effect=ConnectionResetError(10054, "reset")) as shutdown,
                    patch.object(windows_event_loop._ResetSafeSocket, "close", autospec=True, side_effect=socket.socket.close) as close,
                ):
                    if protocol_error:
                        with self.assertRaises(ValueError) as caught:
                            transport._call_connection_lost(None)
                        self.assertIs(caught.exception, protocol_error)
                    else:
                        transport._call_connection_lost(None)
                    transport._call_connection_lost(None)
                    shutdown.assert_called_once_with(socket.SHUT_RDWR)
                    close.assert_called_once_with(owned)
                protocol.connection_lost.assert_called_once_with(None)
                server._detach.assert_called_once()
                self.assertTrue(transport._called_connection_lost)
                self.assertIsNone(transport._sock)
                self.assertIsNone(transport._server)
                self.assertEqual(owned.fileno(), -1)

    def test_plain_and_tls_factory_identity_and_failed_constructor_cleanup(self) -> None:
        loop = windows_event_loop.new_event_loop()
        try:
            self.assertIsInstance(loop, asyncio.ProactorEventLoop)
            for name in ("_make_socket_transport", "_make_ssl_transport"):
                with self.subTest(name=name):
                    original = socket.socket()
                    original.setblocking(False)
                    descriptor = original.fileno()
                    seen = []

                    def fail(_loop, sock, *args, seen=seen, original=original, descriptor=descriptor, **kwargs):
                        seen.append(sock)
                        self.assertIs(sock, original)
                        self.assertIsInstance(sock, windows_event_loop._ResetSafeSocket)
                        self.assertEqual(sock.fileno(), descriptor)
                        self.assertEqual(sock.gettimeout(), 0.0)
                        raise ValueError("transport constructor")

                    with (
                        patch.object(asyncio.ProactorEventLoop, name, fail),
                        self.assertRaisesRegex(ValueError, "transport constructor"),
                    ):
                        getattr(loop, name)(original, object())
                    self.assertEqual(original.fileno(), -1)
                    self.assertEqual(seen[0].fileno(), -1)
        finally:
            loop.close()

    def test_real_600_connections_reset_shutdown_and_subprocess(self) -> None:
        async def scenario() -> None:
            loop = asyncio.get_running_loop()
            errors, protocols = [], []
            loop.set_exception_handler(lambda _loop, context: errors.append(context))

            class Echo(asyncio.Protocol):
                def connection_made(self, transport) -> None:
                    self.transport, self.lost = transport, 0
                    protocols.append(self)

                def data_received(self, data) -> None:
                    self.transport.write(data)

                def connection_lost(self, _error) -> None:
                    self.lost += 1

            server = await loop.create_server(Echo, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            writers = []
            try:
                for _ in range(600):
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    writers.append(writer)
                    writer.write(b"alive")
                    await writer.drain()
                    self.assertEqual(await reader.readexactly(5), b"alive")
                self.assertEqual(len(protocols), 600)
                self.assertTrue(all(protocol.lost == 0 for protocol in protocols))
                self.assertTrue(all(isinstance(protocol.transport._sock, windows_event_loop._ResetSafeSocket) for protocol in protocols))
                self.assertTrue(all(isinstance(writer.transport._sock, windows_event_loop._ResetSafeSocket) for writer in writers))
                child = await asyncio.create_subprocess_exec(
                    sys.executable, "-c", "import sys; sys.stdout.write('child-ok')",
                    stdout=asyncio.subprocess.PIPE,
                )
                output, _ = await child.communicate()
                self.assertEqual((child.returncode, output), (0, b"child-ok"))
                for index, writer in enumerate(writers):
                    if index % 2:
                        writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh", 1, 0))
                        writer.transport.abort()
                    else:
                        writer.close()
                    try:
                        await writer.wait_closed()
                    except ConnectionResetError:
                        pass
                for _ in range(200):
                    if all(protocol.lost == 1 for protocol in protocols):
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(all(protocol.lost == 1 for protocol in protocols))
                self.assertTrue(all(protocol.transport._sock is None for protocol in protocols))
                self.assertEqual(errors, [])
            finally:
                for writer in writers:
                    writer.close()
                server.close()
                await asyncio.wait_for(server.wait_closed(), 3)

        policy = asyncio.get_event_loop_policy()
        with asyncio.Runner(loop_factory=windows_event_loop.new_event_loop) as runner:
            runner.run(asyncio.wait_for(scenario(), 30))
        self.assertIs(asyncio.get_event_loop_policy(), policy)

    def test_shared_cli_hosts_http_then_gracefully_closes_once(self) -> None:
        import uvicorn
        from fastapi import FastAPI

        events, servers, client_errors = [], [], []

        @asynccontextmanager
        async def lifespan(_app):
            events.append(type(asyncio.get_running_loop()).__name__)
            events.append("enter")
            try:
                yield
            finally:
                events.append("exit")

        app = FastAPI(lifespan=lifespan)

        @app.get("/health")
        async def health():
            return {"status": "ok"}

        @app.get("/stop")
        async def stop():
            servers[0].should_exit = True
            return {"stopping": True}

        actual_server = uvicorn.Server

        class ObservedServer(actual_server):
            def __init__(self, config):
                super().__init__(config)
                servers.append(self)

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]

        def browser_requests():
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.5) as reply:
                            self.assertEqual(reply.status, 200)
                            self.assertEqual(reply.read(), b'{"status":"ok"}')
                        break
                    except urllib.error.URLError:
                        time.sleep(0.02)
                else:
                    raise AssertionError("server did not become ready")
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/stop", timeout=2) as reply:
                    self.assertEqual(reply.status, 200)
            except BaseException as error:  # noqa: BLE001 - report thread assertions to the test owner.
                client_errors.append(error)
                if servers:
                    servers[0].should_exit = True

        client = threading.Thread(target=browser_requests, daemon=True)
        client.start()
        with patch.object(uvicorn, "Server", ObservedServer):
            _run_uvicorn(app, host="127.0.0.1", port=port)
        client.join(12)
        self.assertFalse(client.is_alive())
        self.assertEqual(client_errors, [])
        self.assertEqual(events, ["ResetSafeProactorEventLoop", "enter", "exit"])
        self.assertTrue(servers[0].started)

    def test_real_tls_accepted_and_outgoing_sockets_share_the_cleanup_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            certificate, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            certificate.write_text(_CERTIFICATE, encoding="ascii")
            key.write_text(_PRIVATE_KEY, encoding="ascii")
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(certificate, key)
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.check_hostname = False
            client_context.verify_mode = ssl.CERT_NONE

            async def scenario() -> None:
                loop = asyncio.get_running_loop()
                finished = loop.create_future()
                accepted = []

                async def echo(reader, writer):
                    accepted.append(writer.get_extra_info("socket")._sock)
                    try:
                        payload = await reader.readexactly(6)
                        writer.write(payload)
                        await writer.drain()
                    finally:
                        writer.close()
                        await writer.wait_closed()
                        finished.set_result(None)

                server = await asyncio.start_server(echo, "127.0.0.1", 0, ssl=server_context)
                try:
                    port = server.sockets[0].getsockname()[1]
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", port, ssl=client_context, server_hostname="localhost",
                    )
                    outgoing = writer.get_extra_info("socket")._sock
                    writer.write(b"tls-ok")
                    await writer.drain()
                    self.assertEqual(await reader.readexactly(6), b"tls-ok")
                    writer.close()
                    await writer.wait_closed()
                    await finished
                    for sock in [outgoing, *accepted]:
                        self.assertIsInstance(sock, windows_event_loop._ResetSafeSocket)
                        self.assertEqual(sock.fileno(), -1)
                finally:
                    server.close()
                    await server.wait_closed()

            with asyncio.Runner(loop_factory=windows_event_loop.new_event_loop) as runner:
                runner.run(asyncio.wait_for(scenario(), 10))


if __name__ == "__main__":
    unittest.main()
