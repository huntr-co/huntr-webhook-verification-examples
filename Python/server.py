from http.server import HTTPServer, BaseHTTPRequestHandler
import hmac
import base64
import hashlib

SECRET = b'HUNTR_WEBHOOK_SECRET_GOES_HERE'
HUNTR_SIGNATURE_HEADER = 'x-huntr-hmac-sha256'

def verify(received_hmac_header, body):

    # 1) Calculate digital signature by
    # a) Passing request body through Hmax Sha256 algorithm
    # b) Encoding the result from a) to base64

    digest = hmac.new(SECRET, body, hashlib.sha256).digest()
    computed_hmac = base64.b64encode(digest)

    print("computed_hmac: ", computed_hmac)
    print("received_hmac_header: ", received_hmac_header)

    # 2) Compare the result from step 1) to the received signature,
    # if they match, then you can be sure that the message came from Huntr
    return hmac.compare_digest(computed_hmac, received_hmac_header)

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        self.send_response(200)
        self.end_headers()

        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        received_hmac_header = self.headers[HUNTR_SIGNATURE_HEADER]

        if received_hmac_header is None:
            return

        verified = verify(received_hmac_header.encode('utf-8'), body)
        if (verified):
            print("Signature Verified | Safe to continue...")
            # Your regular webhook logic here...
        else:
            print("Could not verify | Signatures do not match...")

httpd = HTTPServer(('localhost', 8000), SimpleHTTPRequestHandler)
httpd.serve_forever()
