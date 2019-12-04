'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const fs = require('fs')
const path = require('path')
const { JWT } = require('@solid/jose')
const { random } = require('../src/crypto')
const testStore = require('./test-storage')

/**
 * Assertions
 */
chai.use(require('dirty-chai'))
chai.use(require('chai-as-promised'))
chai.should()
const expect = chai.expect

/**
 * Code under test
 */
const Provider = require('../src/Provider')
const AccessToken = require('../src/AccessToken')

/**
 * Tests
 */
describe('AccessToken', () => {
  const providerUri = 'https://example.com'
  var provider

  before(function () {
    const configPath = path.join(__dirname, 'config', 'provider.json')

    const storedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'))
    storedConfig.store = testStore()

    provider = new Provider(storedConfig)

    return provider.initializeKeyChain(provider.keys)
  })

  describe('issueForRequest()', () => {
    const subject = { _id: 'user123' }
    const client = { client_id: 'client123' }
    let request, response
    const params = {}
    const scope = ['token']
    const defaultRsUri = 'https://rs.example.com'

    describe('authentication requests', () => {
      let code

      beforeEach(() => {
        request = { params, code, provider, client, subject, scope, defaultRsUri }
        response = {}
      })

      it('should issue an access token', async () => {
        const res = await AccessToken.issueForRequest(request, response)

        expect(res.token_type).to.equal('Bearer')
        expect(res.expires_in).to.equal(1209600)

        const token = await JWT.decode(res.access_token)

        expect(token.type).to.equal('JWS')
        expect(token.header.alg).to.equal('RS256')
        expect(token.payload.iss).to.equal(providerUri)
        expect(token.payload.sub).to.equal('user123')
        expect(token.payload.jti).to.exist()
        expect(token.payload.scope).to.eql(['token'])
        expect(token.payload.aud).to.eql(['client123', 'https://rs.example.com'])
      })
    })

    describe('auth code request', () => {
      let code

      beforeEach(() => {
        code = {
          aud: 'client123',
          sub: 'user123',
          scope: ['token']
        }

        request = { params, code, provider, client, subject }
        response = {}
      })

      it('should issue an access token', () => {
        return AccessToken.issueForRequest(request, response)
          .then(res => {
            expect(res.token_type).to.equal('Bearer')
            expect(res.expires_in).to.equal(1209600)

            return JWT.decode(res.access_token)
          })
          .then(token => {
            expect(token.type).to.equal('JWS')
            expect(token.header.alg).to.equal('RS256')
            expect(token.payload.iss).to.equal(providerUri)
            expect(token.payload.sub).to.equal('user123')
            expect(token.payload.scope).to.eql(['token'])
          })
      })
    })
  })

  describe('issue()', () => {
    let options

    beforeEach(() => {
      options = {
        aud: 'client123',
        sub: 'user123',
        scope: 'openid profile'
      }
    })

    it('should issue an access token', () => {
      const token = AccessToken.issue(provider, options)

      expect(token.payload.iss).to.equal(provider.issuer)
      expect(token.payload.aud).to.equal('client123')
      expect(token.payload.sub).to.equal('user123')
      expect(token.payload.scope).to.equal('openid profile')
    })

    it('should issue an access token with passed in values', () => {
      options.alg = 'RS512'

      const randomId = random(8)
      options.jti = randomId

      const now = Math.floor(Date.now() / 1000)
      options.iat = now

      options.max = 3000

      const token = AccessToken.issue(provider, options)

      expect(token.payload.jti).to.equal(randomId)
      expect(token.payload.iat).to.equal(now)
      expect(token.payload.exp - token.payload.iat).to.equal(3000)

      expect(token.header.alg).to.equal('RS512')
    })

    it('should init with defaults', () => {
      const token = AccessToken.issue(provider, options)

      expect(token.header.alg).to.equal(AccessToken.DEFAULT_SIG_ALGORITHM)
      expect(token.header.kid).to.exist()

      expect(token.payload.jti).to.exist()
      expect(token.payload.exp).to.exist()
      expect(token.payload.iat).to.exist()

      expect(token.payload.exp - token.payload.iat)
        .to.equal(AccessToken.DEFAULT_MAX_AGE)

      expect(token.key).to.exist()
    })
  })
})
