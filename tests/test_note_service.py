import threading
import unittest
from http.client import HTTPConnection
from note_service import NoteServer

class NotesTest(unittest.TestCase):
    def test_http(self):
        with NoteServer(("127.0.0.1", 0)) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            def request(method, key, body=None):
                conn = HTTPConnection(*server.server_address, timeout=3)
                try:
                    conn.request(method, "/note/" + key, body, {"Content-Type": "text/plain"})
                    r = conn.getresponse()
                    return r.status, r.getheader("Cache-Control"), r.read()
                finally:
                    conn.close()
            try:
                self.assertEqual(request("GET", "abc")[:2], (404, "no-cache"))
                self.assertEqual(request("POST", "ab", b"x")[0], 400)
                self.assertEqual(request("POST", "a" * 51, b"x")[0], 400)
                self.assertEqual(request("POST", "a_b", b"x")[0], 400)
                self.assertEqual(request("POST", "abc", b"x" * 1025)[0], 413)
                self.assertEqual(request("POST", "abc", b"x" * 1024)[0], 201)
                self.assertEqual(request("GET", "abc"), (200, "no-cache", b"x" * 1024))
                self.assertEqual(request("POST", "abc", b"")[0], 200)
                self.assertEqual(request("GET", "abc")[2], b"")
                for i in range(99):
                    self.assertEqual(request("POST", f"n{i:03}", b"x")[0], 201)
                self.assertEqual(request("POST", "extra", b"x")[0], 409)
                self.assertEqual(request("POST", "abc", b"updated")[0], 200)
                self.assertEqual(request("GET", "abc")[2], b"updated")
            finally:
                server.shutdown()
                thread.join()
