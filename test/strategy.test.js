import EsiaStrategy from '../lib/strategy';
import { passport } from 'chai';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { parse } from 'url';
import { parse as _parse } from 'querystring';

const sign = {
  key: readFileSync(
    resolve(__dirname, 'fixtures', 'sign', 'private.key'), {encoding: 'utf8'}
  ),
  certificate: readFileSync(
    resolve(__dirname, 'fixtures', 'sign', 'server.pem'), {encoding: 'utf8'}
  )
};

describe('Strategy', function() {

  describe('constructed', () => {
    const strategy = new EsiaStrategy({
      clientID: 'ABC123',
      key: sign.key,
      certificate: sign.certificate,
      callbackURL: 'https://www.example.net/auth/example/callback'
    }, () => {});
    
    it('should be named esia', () => {
      expect(strategy.name).to.equal('esia');
    });
  });

  describe('constructed with undefined options', () => {
    it('should throw', () => {
      expect(() => {
        const strategy = new EsiaStrategy(undefined, () => {});
      }).to.throw(Error);
    });
  });
  
  describe('authorization request with documented parameters', () => {
    const strategy = new EsiaStrategy({
      clientID: 'ABC123',
      key: sign.key,
      certificate: sign.certificate,
      callbackURL: 'https://www.example.net/auth/example/callback'
    }, () => {});
    
    let urlParams;
  
    before((done) => {
      passport.use(strategy)
        .redirect((u) => {
          urlParams = parse(u);
          done();
        })
        .req((req) => {
          req.session = {};
        })
        .authenticate({ state: 'TEST123', accessType: 'offline' });
    });
  
    it('should be redirected', () => {
      expect(urlParams.host).to.equal('esia-portal1.test.gosuslugi.ru');
      expect(urlParams.pathname).to.equal('/aas/oauth2/ac');
      const query = _parse(urlParams.query);
      expect(Object.keys(query)).to.have.members([
        'timestamp', 'access_type', 'client_secret', 'response_type', 'scope', 'state', 'client_id', 'redirect_uri'
      ]);
      expect(query.redirect_uri).to.equal('https://www.example.net/auth/example/callback');
      expect(query.response_type).to.equal('code');
      expect(query.access_type).to.equal('offline');
      expect(query.client_id).to.equal('ABC123');
      expect(query.scope).to.equal('fullname email');
      expect(query.state).to.equal('TEST123');
    });
  });

});
