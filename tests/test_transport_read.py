"""读响应这一层：TLS 上不能带 flags，首字节还得量得准。

背景（真踩到的）：`_read_response_inner` 原来用 `sock.recv(1, socket.MSG_PEEK)`
判断"服务端是不是一声不吭就断了"。`socket.socket` 认这个 flags，
`ssl.SSLSocket.recv` 不认——HTTPS 目标一律炸在
`ValueError: non-zero flags not allowed in calls to recv() on <class 'ssl.SSLSocket'>`，
而且是 ValueError 不是 OSError，穿过了 `_read_response` 的兜底，
把一次普通探测升级成整轮演练失败。
"""
import socket
import threading
import time
import unittest

from pta.transport import TransportError, _read_response


class StrictSock:
    """只允许 `recv(n)` 的 socket 假身：模拟 SSLSocket 对 flags 的态度。"""

    def __init__(self, sock):
        self._sock = sock
        self.recv_calls = []

    def recv(self, n, *flags):
        if flags:
            raise ValueError("non-zero flags not allowed in calls to recv() "
                             "on <class 'ssl.SSLSocket'>")
        self.recv_calls.append(n)
        return self._sock.recv(n)

    def recv_into(self, buf, *flags):
        if flags:
            raise ValueError("non-zero flags not allowed in calls to recv_into() "
                             "on <class 'ssl.SSLSocket'>")
        return self._sock.recv_into(buf)

    def makefile(self, *args, **kwargs):
        return self._sock.makefile(*args, **kwargs)

    def close(self):
        self._sock.close()


class SocketPairCase(unittest.TestCase):
    def pair(self, reply):
        srv, cli = socket.socketpair()
        self.addCleanup(srv.close)
        self.addCleanup(cli.close)

        def serve():
            try:
                srv.recv(65536)
                srv.sendall(reply)
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()
        cli.sendall(b"GET /x HTTP/1.1\r\nHost: app.test\r\n\r\n")
        return cli


class ReadResponseTest(SocketPairCase):
    def test_flags_free_socket_reads_the_response(self):
        """SSLSocket 那种不吃 flags 的 socket 也要能读。"""
        cli = self.pair(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: 1\r\n\r\nhello")
        sock = StrictSock(cli)
        res = _read_response(sock, time.perf_counter())
        self.assertEqual(res.status, 200)
        self.assertEqual(res.body, b"hello")
        self.assertEqual(dict(res.headers)["X-A"], "1")
        self.assertEqual(sock.recv_calls, [1])          # 只读首字节那一次

    def test_first_byte_comes_back_through_the_replay(self):
        """首字节被读掉之后必须回放，否则状态行会少一个字符。"""
        cli = self.pair(b"HTTP/1.1 204 No Content\r\n\r\n")
        res = _read_response(StrictSock(cli), time.perf_counter())
        self.assertEqual(res.status, 204)
        self.assertEqual(res.body, b"")

    def test_immediate_close_is_a_transport_error(self):
        srv, cli = socket.socketpair()
        self.addCleanup(srv.close)
        self.addCleanup(cli.close)
        threading.Thread(target=srv.close, daemon=True).start()
        with self.assertRaises(TransportError) as caught:
            _read_response(StrictSock(cli), time.perf_counter())
        self.assertIn("连接被立即关闭", str(caught.exception))

    def test_first_byte_time_is_taken_after_the_byte_arrives(self):
        cli = self.pair(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        time.sleep(0.01)
        res = _read_response(StrictSock(cli), time.perf_counter())
        self.assertGreaterEqual(res.t_first_byte, res.t_send)


if __name__ == "__main__":
    unittest.main()
