const http = require('http')
const SECRET = 'HUNTR_WEBHOOK_SECRET_GOES_HERE'
const crypto = require('crypto')

const verify = (receivedHmacHeader, body) => {
  // 1) Calculate digital signature by
  // a) Passing request body through Hmax Sha256 algorithm
  // b) Encoding the result from a) to base64
  const hmac = crypto.createHmac('sha256', SECRET);
  const computedHmac = hmac.update(body).digest('base64');

  console.log("computedHmac: ", computedHmac);
  console.log("receivedHmacHeader: ", receivedHmacHeader);

  // 2) Compare the result from step 1) to the received signature,
  // if they match, then you can be sure that the message came from Huntr
  return receivedHmacHeader == computedHmac
}

//create a server object:
http.createServer(function (req, res) {
  let body = '';
  req.on('data', chunk => body += chunk.toString());
  req.on('end', () => {

    const receivedHmacHeader = req.headers['x-huntr-hmac-sha256']
    const verified = verify(receivedHmacHeader, body)

    if (verified)
      // Your regular webhook logic here...
      console.log("Signature Verified | Safe to continue...")
    else
      console.log("Could not verify | Signatures do not match...")

    res.end('ok');
  });

  res.end(); //end the response

}).listen(8080); //the server object listens on port 8080
