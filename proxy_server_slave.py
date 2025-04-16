import http.server
import socketserver
import socket
from urllib.parse import urlparse
from datetime import datetime
import sqlite3
# Abdulkader Alrezej
class ProxyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def get_network_from_db(self):
        db_path = '/mnt/cerr/main_sqlite3_database.db'
        connection = sqlite3.connect(db_path)
        cursor = connection.cursor()
        cursor.execute("SELECT name_network FROM info_admin")
        network_name = cursor.fetchone()[0]
        connection.close()
        return network_name
    def do_GET(self):
        parsed_url = urlparse(self.path)
        hostname = self.headers.get('Host')
        normalized_hostname = hostname.replace('www.', '') if hostname else ''
        network_name = self.get_network_from_db()
        if normalized_hostname == network_name:
            self.send_response(301)
            self.send_header('Location', 'http://[2001:db8::1]:8080')
            self.end_headers()
            return

        # Microsoft -1
        elif normalized_hostname == 'ipv6.msftconnecttest.com' and parsed_url.path == '/connecttest.txt':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Microsoft Connect Test")
        elif normalized_hostname == 'www.msftconnecttest.com' and parsed_url.path == '/connecttest.txt':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Microsoft Connect Test")
        elif normalized_hostname == 'msftconnecttest.com' and parsed_url.path == '/connecttest.txt':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Microsoft Connect Test")
        # Microsoft -2
        elif normalized_hostname == 'www.msftncsi.com' and parsed_url.path == '/ncsi.txt':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Microsoft NCSI")
        elif normalized_hostname == 'msftncsi.com' and parsed_url.path == '/ncsi.txt':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Microsoft NCSI")


        # Apple -1
        elif normalized_hostname == 'www.captive.apple.com' and parsed_url.path == '/hotspot-detect.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")

        elif normalized_hostname == 'captive.apple.com' and parsed_url.path == '/hotspot-detect.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")


        # Apple -2
        elif normalized_hostname == 'www.apple.com' and parsed_url.path == '/library/test/success.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")

        elif normalized_hostname == 'apple.com' and parsed_url.path == '/library/test/success.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")

        # Apple -3
        elif normalized_hostname == 'www.captive.apple.com' and parsed_url.path == '/hotspot-detect.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Success")
        elif normalized_hostname == 'captive.apple.com' and parsed_url.path == '/hotspot-detect.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Success")

        # Apple -4
        elif normalized_hostname == 'www.apple.com' and parsed_url.path == '/library/test/success.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Success")
        elif normalized_hostname == 'apple.com' and parsed_url.path == '/library/test/success.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Success")


        # Gnome
        elif normalized_hostname == 'www.nmcheck.gnome.org' and parsed_url.path == '/check_network_status.txt':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"NetworkManager is online")
        elif normalized_hostname == 'nmcheck.gnome.org' and parsed_url.path == '/check_network_status.txt':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"NetworkManager is online")


        # KDE -1
        elif normalized_hostname == 'www.networkcheck.kde.org' and parsed_url.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"OK")
        elif normalized_hostname == 'networkcheck.kde.org' and parsed_url.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"OK")

        # KDE -2
        elif normalized_hostname == 'www.networkcheck.kde.org' and parsed_url.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"OK")
        elif normalized_hostname == 'networkcheck.kde.org' and parsed_url.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"OK")


        # Google Android system -1

        elif normalized_hostname == 'connectivitycheck.gstatic.com' and parsed_url.path == '/generate_204':
            self.send_response(204)
            self.end_headers()

        elif normalized_hostname == 'clients3.google.com' and parsed_url.path == '/generate_204':
            self.send_response(204)
            self.end_headers()

        elif normalized_hostname == 'connect.rom.miui.com' and parsed_url.path == '/generate_204':
            self.send_response(204)
            self.end_headers()

        else:
            self.send_response(403)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            client_ip = self.client_address[0]
            server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>IPv6Spot Server</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        margin: 0;
                        padding: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        color: #333;
                    }}
                    .container {{
                        text-align: center;
                        background-color: #fff;
                        padding: 20px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        border-radius: 8px;
                    }}
                    h1 {{
                        font-size: 24px;
                        color: #e74c3c;
                    }}
                    p {{
                        font-size: 16px;
                    }}
                    .footer {{
                        margin-top: 20px;
                        font-size: 14px;
                        color: #777;
                    }}
                    .footer p.main-name {{
                        font-size: 20px;
                        font-weight: bold;
                        color: #333;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Access Denied</h1>
                    <p>The requested URL <strong>{hostname}</strong> has been blocked by your network administrator.</p>
                    <div class="footer">
                        <p class="main-name">IPv6Spot</p>
                        <p>Abdulkader Alrezej</p>
                        <p>Server Time: {server_time}</p>
                        <p>Client IP: {client_ip}</p>
                    </div>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode('utf-8'))
class CustomIPv6Server(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
def start_server():
    PORT = 80
    with CustomIPv6Server(('2002:db7::2', PORT), ProxyHTTPRequestHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    start_server()
