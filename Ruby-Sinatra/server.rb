require 'bundler' ; Bundler.require

SECRET = 'HUNTR_WEBHOOK_SECRET_GOES_HERE'
HUNTR_SIGNATURE_HEADER = 'HTTP_x_huntr_hmac_sha256'.upcase

def verify(received_hmac_header, payload_body)

  # 1) Calculate digital signature by
  # a) Passing request body through Hmax Sha256 algorithm
  # b) Encoding the result from a) to base64

  digest = OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha256"), SECRET, payload_body)
  computed_hmac = Base64.strict_encode64(digest)

  p "Computed HMAC: #{computed_hmac}"
  p "Received Header: #{received_hmac_header}"

  # 2) Compare the result from step 1) to the received signature,
  # if they match, then you can be sure that the message came from Huntr

  return computed_hmac == received_hmac_header
end

post '/' do

  request.body.rewind
  payload_body = request.body.read
  received_hmac_header = request.env[HUNTR_SIGNATURE_HEADER]
  verified = verify(received_hmac_header, payload_body)

  if verified
    p "Signature Verified | Safe to continue..."
  else
    p "Could not verify | Signatures do not match..."
  end

end
