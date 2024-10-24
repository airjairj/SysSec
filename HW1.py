import http.server
import ssl
import os

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = 'index.html'
        elif self.path.startswith('/Risorse/Img/'):
            # Allow access to images in the Risorse/Img directory
            pass
        elif self.path == '/certificate':
            self.serve_certificate()
            return
        else:
            self.send_error(403, "Forbidden")
            return
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def serve_certificate(self):
        cert_path = r"C:\Users\hp\Documents\Esami In Corso\System Sec\Homework\SysSec\Risorse\certificate.crt"
        try:
            with open(cert_path, 'r') as cert_file:
                cert_content = cert_file.read()
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(cert_content.encode('utf-8'))
        except Exception as e:
            self.send_error(500, f"Error reading certificate: {e}")

# Define server address and port
server_address = ('localhost', 4443)

# Create HTTP server
httpd = http.server.HTTPServer(server_address, CustomHTTPRequestHandler)

# Get paths from environment variables
cert_path = r"C:\Users\hp\Documents\Esami In Corso\System Sec\Homework\SysSec\Risorse\certificate.crt"
key_path = r"C:\Users\hp\Documents\Esami In Corso\System Sec\Homework\SysSec\Risorse\private.key"

if not cert_path or not key_path:
    raise ValueError("CERT_PATH and KEY_PATH missing")

# Create SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=cert_path, keyfile=key_path)

# Wrap the server socket with SSL context
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

# Start the server
print("Serving on https://localhost:4443")
httpd.serve_forever()