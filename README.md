# passport-esia

Модуль для Passport.js авторизации через ЕСИА с поддержкой ГОСТовского шифрования.

- не зависит от системного OpenSSL, всё шифрование на чистом JS через интерфейсы WebCrypto
- проверено в production окружении ЕСИА
- автоматически раскодирует и отдает JWT access token ЕСИА с проверкой подписи (если указан публичный ключ и только RSA)
- все ключи и сертификаты задаются в формате PEM

## Использование

Устанавливается стандартно. Подключается аналогично любому модулю Passport. Пример:

	const passport = require('passport'),
			EsiaStrategy = require('passport-esia').Strategy;
	
	passport.use(new EsiaStrategy({
		ca_pub_key: "-----BEGIN PUBLIC KEY-----\
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg4/V4iNjYrC4gBSM7OlD\
	bYHNqpyfUYkoRoZ+GGcTU/Vd47srTLlhFADtTcC4GangTY9p1zpm1DGO7nhVRb6I\
	UKWt49jwRApvH2k/vo4Nlou6bwqZeeg1BVJZRGBH5UtnZ5k5gR3qKyntb+RpG3sA\
	WfZQicH6yfoWbBS6ypfJ0EJ7GNxaeAn5akjSYMwFx4mRVG2pYo+Ly2jjd5XlbWhq\
	nMle6sROvR4y7SaudqW2Bg7sE/8ZrYGJRBdgMn5d83M6uxOEhp4yp8TP3+NnXAxI\
	keK4IMaBMwzfw/OGjbS8a/UMnN1EMT4bkXbk0z/Y/5guI2H1MrrgsIQs6VQorf9J\
	zwIDAQAB\
	-----END PUBLIC KEY-----",	// not required - only to verify JWT signature
		key: "-----BEGIN PRIVATE KEY-----\
	-----END PRIVATE KEY-----",
		certificate: "-----BEGIN CERTIFICATE-----\
	-----END CERTIFICATE-----",
		type: 'gost',		// or 'rsa' by default
		clientID: '<ID>',
		scope: 'fullname birthdate gender id_doc contacts mobile',
		callbackURL: 'https://example.com/esia',
		authorizationURL: 'https://esia.gosuslugi.ru/aas/oauth2/ac',
		tokenURL: 'https://esia.gosuslugi.ru/aas/oauth2/te',
	}, 
	async function(accessToken, refreshToken, token_payload, cb) {
		let info = { messages: [], esia: null };
		let user = false;
		
		if (token_payload) {		
			let esia = {
				oid: token_payload['urn:esia:sbj_id'],
				access: accessToken,
				refresh: refreshToken				
			};
			
			user = await User.updateOne({ esia_id: esia.oid }, { esia_tokens: _.omit(esia, ['oid']) });
			
			// If user not found - return ESIA info out of passport so other routines can use it
			if (!user) {
				info.esia = esia;
			}
		} else {
			info.messages.push('Ошибка проверки подписи ответа ЕСИА.');
		}
				
		return cb(null, user || false, info);
	}
	));

Для последующих вызовов API ЕСИА можно использовать встроенный в стратегию OAuth2, что-то типа:

	let esia = {
		oid: token_payload['urn:esia:sbj_id'],
		access: accessToken,
		refresh: refreshToken				
	};

	let EsiaStrategy = passport._strategy('esia');
	EsiaStrategy._oauth2.useAuthorizationHeaderforGET(true);
	EsiaStrategy._oauth2.getAsync = util.promisify(EsiaStrategy._oauth2.get);

	try {
		let userBaseUrl = 'https://esia.gosuslugi.ru/rs/prns/'+esia.oid;
		esia_user = JSON.parse(await EsiaStrategy._oauth2.getAsync(userBaseUrl, esia.access));
		if (!esia_user) {
			throw 'ESIA user empty';
		}
		if (esia_user.status != 'REGISTERED') {
			throw 'ESIA user not registered';
		}
		if (!esia_user.trusted) {
			throw 'ESIA user not verified';
		}
	} catch (e) {
		let err_data = {};
	
		if (e.data) {
			err_data = JSON.parse(e.data);
		}
	
		// Expired token
		// TODO: repeat request and request fresh token
		if (err_data.code && err_data.code == 'ESIA-005013') {
			console.log('Устарели ключи авторизации - пожалуйста, повторите вход в ЕСИА.');
		}
		console.log('Ошибка получения данных пользователя из ЕСИА.');
	}

***

Copyright (c) 2020 skylord <me@skylord.ru>

Copyright (c) 2018 inkz <inkz@xakep.ru>
