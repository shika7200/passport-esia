
import { inherits } from 'util';
import uuidv4 from 'uuid/v4';
import { decode, toBuffer } from 'base64url';
import OAuth2Strategy, { call, prototype } from 'passport-oauth2';
import { urlSafe, encrypt, getTimestamp } from './utils';

import { Crypto } from "@peculiar/webcrypto";
const crypto_common = new Crypto();
import { subtle as _subtle } from "node-gost";


/**
 * `Strategy` constructor.
 *
 * Options:
 *   - `clientID`
 *   - `ca_pub_key`
 *   - `certificate`
 *   - `key`
 *   - `type` ("rsa" or "gost")
 *   - `password`
 *   - `scope`
 *   - `authorizationURL`
 *   - `callbackURL`
 *   - `tokenURL`
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @access public
 */
function EsiaStrategy(options, verify) {
  options = options || {};

  if (!options.key) { throw new TypeError('EsiaStrategy requires a key option'); }
  if (!options.certificate) { throw new TypeError('EsiaStrategy requires a certificate option'); }
  if (!options.callbackURL) { throw new TypeError('EsiaStrategy requires a callbackURL option'); }

  options.type = options.type || 'rsa';
  options.scope = options.scope || 'fullname email';
  options.authorizationURL = options.authorizationURL || 'https://esia-portal1.test.gosuslugi.ru/aas/oauth2/ac';
  options.tokenURL = options.tokenURL || 'https://esia-portal1.test.gosuslugi.ru/aas/oauth2/te';

  // Convert PEM certificate/keys to ArrayBuffer DERs
  let key_bin = Buffer.from(options.key.replace('-----BEGIN PRIVATE KEY-----', '').replace('-----END PRIVATE KEY-----', '').replace(/[\s\r\n\x0B\x0C\u0085\u2028\u2029]+/g, ''), 'base64');
  key_bin = key_bin.buffer.slice(key_bin.byteOffset, key_bin.byteOffset + key_bin.byteLength);

  let certificates_bin = options.certificate
    .split('-----END CERTIFICATE-----')
    .map(el => el ? el.replace('-----BEGIN CERTIFICATE-----', '').replace(/[\s\r\n\x0B\x0C\u0085\u2028\u2029]+/g, '') : undefined)
    .filter(el => el ? true : false)
    .map(el => { let b = Buffer.from(el, 'base64'); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); })
    .filter(el => el ? true : false);

  let ca_pub_key_bin = options.ca_pub_key ? Buffer.from(options.ca_pub_key.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace(/[\s\r\n\x0B\x0C\u0085\u2028\u2029]+/g, ''), 'base64') : null;  
  if (ca_pub_key_bin) {
    ca_pub_key_bin = ca_pub_key_bin.buffer.slice(ca_pub_key_bin.byteOffset, ca_pub_key_bin.byteOffset + ca_pub_key_bin.byteLength);
  }

  this._esia = {
    ca_pub_key: ca_pub_key_bin,
    key: key_bin,
    certificate: certificates_bin,
    type: options.type
  };

  call(this, options, verify);
  this.name = 'esia';

};

// Inherit from `OAuth2Strategy`.
inherits(EsiaStrategy, OAuth2Strategy);

EsiaStrategy.prototype.authenticate = async function (req, options) {
  options = options || {};
  if (!options.state) {
    options.state = uuidv4();
  }
  
  options.authorizationParams = await this.authorizationParamsAsync(options);
  options.tokenParams = await this.tokenParamsAsync(options);
  
  prototype.authenticate.call(this, req, options);
};

EsiaStrategy.prototype.userProfile = function(accessToken, done) {
  if (!accessToken) {
    return done(new Error('Got empty accessToken from ESIA'), null);
  }
    
  let token_parts = accessToken.split('.');
  let token_header = JSON.parse(decode(token_parts[0]));
  let token_data = JSON.parse(decode(token_parts[1]));

  let token_signing_data = Buffer.from(token_parts.slice(0, 2).join('.'), 'utf8');
  token_signing_data = token_signing_data.buffer.slice(token_signing_data.byteOffset, token_signing_data.byteOffset + token_signing_data.byteLength);

  let token_signature = toBuffer(token_parts[2]);
  token_signature = token_signature.buffer.slice(token_signature.byteOffset, token_signature.byteOffset + token_signature.byteLength);

  if (this._esia.ca_pub_key) {
    let subtle = crypto_common.subtle;
    let algo = { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' }};
    
    // Not tested as now ESIA returns JWT token with RS256 signature even if client requests were signed with GOST
    if (token_header.alg == 'GOST3410_2012_256') {
      subtle = _subtle;
      algo = { name: 'GOST R 34.10-256', hash: { name: 'GOST R 34.11-256' }};
    }
    
    return subtle.importKey('spki', this._esia.ca_pub_key, algo, false, ['verify'])
      .then(key => subtle.verify(algo, key, token_signature, token_signing_data))
      .then(isValid => done(isValid ? null : new Error('Error verifying ESIA JWT signature'), token_data) );
  } else {
    return done(null, token_data);
  }
  
};

/**
 * Parameters to be included in the authorization request.
 *
 * @param {Object} options
 * @param {String} options.state
 * @return {Object}
 * @access protected
 */
EsiaStrategy.prototype.authorizationParamsAsync = async function(options) {
  const timestamp = getTimestamp();
  const message = this._scope + timestamp + this._oauth2._clientId + options.state;
  const secret = await encrypt(message, this._esia.certificate, this._esia.key, this._esia.type);
  return {
    timestamp,
    access_type: options.accessType || 'online',
    client_secret: urlSafe(secret)
  };
};

EsiaStrategy.prototype.authorizationParams = function(options) {
  return options.authorizationParams || {};
};

/**
 * Parameters to be included in the authorization request.
 *
 * @param {Object} options
 * @param {String} options.state
 * @return {Object}
 * @access protected
 */
EsiaStrategy.prototype.tokenParamsAsync = async function(options) {
  const timestamp = getTimestamp();
  const message = this._scope + timestamp + this._oauth2._clientId + options.state;
  const secret = await encrypt(message, this._esia.certificate, this._esia.key, this._esia.type);
  
  // Oauth module doesn't support dynamic client_secret so we have to override the one it saved on init
  this._oauth2._clientSecret = urlSafe(secret);
  
  return {
    timestamp,
    scope: this._scope,
    state: options.state,
    token_type: 'Bearer',
    client_secret: urlSafe(secret)
  };
};

EsiaStrategy.prototype.tokenParams = function(options) {
  return options.tokenParams || {};
};

export default EsiaStrategy;
