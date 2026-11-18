#!/usr/bin/env python3
"""In-memory HTTP notes; Python standard library only."""
import argparse
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class NoteServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address):
        super().__init__(address, NoteHandler)
        self.notes = {}
        self.lock = threading.Lock()


class NoteHandler(BaseHTTPRequestHandler):
    timeout = 10

    def reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if self.command == "GET":
            self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def note_id(self):
        match = re.fullmatch(r"/note/([A-Za-z0-9]{3,50})", urlsplit(self.path).path)
        if match is None:
            self.reply(400, b"Invalid note ID.\n")
            return None
        return match[1]

    def do_GET(self):
        key = self.note_id()
        if key is None:
            return
        with self.server.lock:
            body = self.server.notes.get(key)
        self.reply(404, b"Note not found.\n") if body is None else self.reply(200, body)

    def do_POST(self):
        key = self.note_id()
        if key is None:
            return
        if self.headers.get_content_type() != "text/plain":
            self.reply(415, b"Expected text/plain.\n")
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self.reply(400, b"Use Content-Length; Transfer-Encoding is unsupported.\n")
            return
        lengths = self.headers.get_all("Content-Length", [])
        if not lengths:
            self.reply(411, b"Content-Length required.\n")
            return
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
            self.reply(400, b"Invalid Content-Length.\n")
            return
        length = lengths[0].lstrip("0") or "0"
        if len(length) > 4 or int(length) > 1024:
            self.reply(413, b"Maximum note size is 1024 bytes.\n")
            return
        length = int(length)
        try:
            body = self.rfile.read(length)
        except TimeoutError:
            self.reply(408, b"Request timed out.\n")
            return
        if len(body) != length:
            self.reply(400, b"Incomplete body.\n")
            return
        try:
            body.decode("utf-8")
        except UnicodeDecodeError:
            self.reply(400, b"Expected UTF-8 text.\n")
            return
        with self.server.lock:
            exists = key in self.server.notes
            full = not exists and len(self.server.notes) >= 100
            if not full:
                self.server.notes[key] = body
        if full:
            self.reply(409, b"Maximum of 100 notes reached.\n")
        else:
            self.reply(200 if exists else 201)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    with NoteServer((args.host, args.port)) as server:
        print(f"Listening on http://{args.host}:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
