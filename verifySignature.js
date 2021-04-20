/* ******************************************************************************
 * Signing Secret Varification
 * 
 * Signing secrets replace the old verification tokens. 
 * Slack sends an additional X-Slack-Signature HTTP header on each HTTP request.
 * The X-Slack-Signature is just the hash of the raw request payload 
 * (HMAC SHA256, to be precise), keyed by your app’s Signing Secret.
 *
 * More info: https://api.slack.com/docs/verifying-requests-from-slack
 *
 * Tomomi Imura (@girlie_mac)
 * ******************************************************************************/

const crypto = require('crypto');
const timingSafeCompare = require('tsscmp');

const isVerified = (req) => { 
  const signature = req.headers['X-Slack-Signature'];
  const timestamp = req.headers['X-Slack-Request-Timestamp'];
  const hmac = crypto.createHmac('sha256', process.env.SLACK_SIGNING_SECRET);
  const [version, hash] = signature.split('=');
    const slack_signing_secret = process.env.SLACK_SIGNING_SECRET
  // Check if the timestamp is too old
  const fiveMinutesAgo = ~~(Date.now() / 1000) - (60 * 5);
  if (timestamp < fiveMinutesAgo) return false;

  const sig_basestring = hmac.update(`${version}:${timestamp}:${req.rawBody}`);
//   sig_basestring = 'v0:' + timestamp + ':' + request_body
    
// my_signature = 'v0=' + hmac.compute_hash_sha256(
//     slack_signing_secret,
//     sig_basestring
//     ).hexdigest()

  // check that the request signature matches expected value
  return timingSafeCompare(hmac.digest('hex'), hash);
}; 
  
module.exports = { isVerified };