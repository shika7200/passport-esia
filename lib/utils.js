const asn1js = require("asn1js");
const pkijs = require("pkijs");

const webcrypto = require("@peculiar/webcrypto");
const crypto_common = new webcrypto.Crypto();
const crypto_common_engine = new pkijs.CryptoEngine({ name: 'common', crypto: crypto_common, subtle: crypto_common.subtle });

const crypto_gost = require("node-gost");
const crypto_gost_engine = new pkijs.CryptoEngine({ name: 'gost', crypto: crypto_gost, subtle: crypto_gost.subtle });
		
// Monkey patching crypto engine for GOST values used by ESIA
crypto_gost_engine.importKey = crypto_gost_engine.subtle.importKey;

crypto_gost_engine.getOIDByAlgorithmOrig = crypto_gost_engine.getOIDByAlgorithm;
crypto_gost_engine.getOIDByAlgorithm = function (algorithm) {
	if (algorithm.name.toUpperCase() == 'GOST R 34.10') {
		if (algorithm.version == 2012) {
			if (algorithm.length == 256) {
				return '1.2.643.7.1.1.1.1';						
			}
		}
	}
	
	if (algorithm.name.toUpperCase() == 'GOST R 34.11-256') {
		return '1.2.643.7.1.1.2.2';
	}
	return this.getOIDByAlgorithmOrig(algorithm);
}

crypto_gost_engine.getSignatureParametersOrig = crypto_gost_engine.getSignatureParameters;
crypto_gost_engine.getSignatureParameters = async function (privateKey, hashAlgorithm) {
	if (hashAlgorithm.toUpperCase() == 'GOST R 34.11-256') {
		const parameters = this.getAlgorithmParameters(privateKey.algorithm.name, "sign");
		parameters.algorithm.hash.name = hashAlgorithm;
		const signatureAlgorithm = new pkijs.AlgorithmIdentifier();
		signatureAlgorithm.algorithmId = this.getOIDByAlgorithm(parameters.algorithm);
		return { signatureAlgorithm:signatureAlgorithm, parameters:parameters };
	}
	return this.getSignatureParametersOrig(privateKey, hashAlgorithm);
}

crypto_gost_engine.getAlgorithmParametersOrig = crypto_gost_engine.getAlgorithmParameters;
crypto_gost_engine.getAlgorithmParameters = function (algorithmName, operation) {
	if (algorithmName.toUpperCase() == 'GOST R 34.10' && operation.toLowerCase() == "sign") {
		return {
			algorithm: {
				name: 'GOST R 34.10',
				version: 2012,
				length: 256,
				hash: {
					name: 'GOST R 34.11-256'
				}
			},
			usages: ["sign"]
		};
	}
	return this.getAlgorithmParametersOrig(algorithmName, operation);
}


exports.urlSafe = (str) =>
  str.trim()
    .split('+')
    .join('-')
    .split('/')
    .join('_')
    .replace('=', '');

exports.getTimestamp = (value) => {
  const now = value ? new Date(value) : new Date();
  const dateFormat = {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  };
  const [date, time] = now.toLocaleString('en', dateFormat).split(', ');
  const [month, day, year] = date.split('/');
  const [hour, min, sec] = time.split(':');
  const tz = now.toString().match(/GMT[\+|\-](\d*)/)[1];
  return `${year}.${month}.${day} ${hour}:${min}:${sec} +${tz}`;
};

exports.encrypt = async (message, certificate, key, crypto_type) => {
	crypto_type = crypto_type || 'rsa';
	let algo = {};

	// Load appropriate crypto engine
	if (crypto_type == 'gost') {
		algo = { name: 'GOST R 34.10-256', hash: { name: 'GOST R 34.11-256' }};
		pkijs.setEngine('gost', crypto_gost, crypto_gost_engine);
	} else {		
		algo = { name: "RSASSA-PKCS1-v1_5", hash: { name: 'SHA-256' }};
		pkijs.setEngine('common', crypto_common, crypto_common_engine);
	}
	
	let crypto = pkijs.getCrypto();
	
	// Prepare binary message
	let message_bin = Buffer.from(message, 'utf8');
	message_bin = message_bin.buffer.slice(message_bin.byteOffset, message_bin.byteOffset + message_bin.byteLength);
	
	// Prepare certificates and key in appropriate format
	let certificates_obj = certificate.map(el => new pkijs.Certificate({ schema: asn1js.fromBER(el).result }) );
	let key_obj = await crypto.importKey('pkcs8', key, algo, true, ['sign']);

	// Create signed data info
  let cmsSigned = new pkijs.SignedData({
		version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: "1.2.840.113549.1.7.1", // "data" content type
      eContent: new asn1js.OctetString({ valueHex: message_bin })
    }),
    signerInfos: [
      new pkijs.SignerInfo({
        sid: new pkijs.IssuerAndSerialNumber({
          issuer: certificates_obj[0].issuer,
          serialNumber: certificates_obj[0].serialNumber
        })
      })
    ],
    certificates: [certificates_obj[0]]
  });
	
	await cmsSigned.sign(key_obj, 0, algo.hash.name);
	
	let cmsSignedSchema = new pkijs.ContentInfo({
		contentType: "1.2.840.113549.1.7.2",
		content: cmsSigned.toSchema(true)
	}).toSchema();
	
	let block1 = cmsSignedSchema.valueBlock.value[1];
	let block2 = block1.valueBlock.value[0];
	cmsSignedSchema.lenBlock.isIndefiniteForm = block1.lenBlock.isIndefiniteForm = block2.lenBlock.isIndefiniteForm = true;
	cmsSignedBuffer = cmsSignedSchema.toBER(false);

	return Buffer.from(cmsSignedBuffer).toString('base64');
};
