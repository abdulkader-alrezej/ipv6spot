import http.server
import socketserver
import socket
from urllib.parse import urlparse
# Abdulkader Alrezej
class ProxyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://[2001:db8::1]:8080')
        self.end_headers()
    def log_message(self, format, *args):
        return
    
class CustomIPv6Server(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6

def start_server():
    PORT = 8381
    with CustomIPv6Server(('2002:db9::2', PORT), ProxyHTTPRequestHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    start_server()

