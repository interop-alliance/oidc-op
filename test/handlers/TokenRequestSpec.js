/* eslint-disable camelcase */
'use strict'

/**
 * Test dependencies
 */
const cwd = process.cwd()
const path = require('path')
const chai = require('chai')
const sinon = require('sinon')
const HttpMocks = require('node-mocks-http')
const testStore = require('../test-storage')

/**
 * Assertions
 */
chai.use(require('dirty-chai'))
chai.use(require('sinon-chai'))
chai.should()
const expect = chai.expect

/**
 * Code under test
 */
const TokenRequest = require(path.join(cwd, 'src', 'handlers', 'TokenRequest'))
const AccessToken = require(path.join(cwd, 'src', 'AccessToken'))
const IDToken = require(path.join(cwd, 'src', 'IDToken'))

/**
 * Tests
 */
describe('TokenRequest', () => {
  /**
   * Handle
   */
  describe('handle', () => {})

  /**
   * Constructor
   */
  describe('constructor', () => {
    let params, request

    before(() => {
      params = { grant_type: 'authorization_code' }
      const req = { method: 'POST', body: params }
      const res = {}
      const provider = { host: {} }
      request = new TokenRequest(req, res, provider)
    })

    it('should set "params" from request body', () => {
      request.params.should.equal(params)
    })

    it('should set "grantType" from params', () => {
      request.grantType.should.equal(params.grant_type)
    })
  })

  /**
   * Get Grant Type
   */
  describe('getGrantType', () => {
    it('should return the "grant_type" parameter', () => {
      TokenRequest.getGrantType({
        params: {
          grant_type: 'authorization_code'
        }
      }).should.equal('authorization_code')
    })
  })

  /**
   * Supported Grant Type
   */
  describe('supportedGrantType', () => {
    let res, host, provider

    beforeEach(() => {
      res = {}
      host = {}
      provider = { host, grant_types_supported: ['authorization_code'] }
    })

    it('should return true with a supported response type parameter', () => {
      const params = { grant_type: 'authorization_code' }
      const req = { method: 'POST', body: params }
      const request = new TokenRequest(req, res, provider)
      request.supportedGrantType().should.equal(true)
    })

    it('should return false with an unsupported response type parameter', () => {
      const params = { grant_type: 'other' }
      const req = { method: 'POST', body: params }
      const request = new TokenRequest(req, res, provider)
      request.supportedGrantType().should.equal(false)
    })
  })

  /**
   * Validate
   */
  describe('validate', () => {
    describe('with valid params', () => {
      it('should not throw error', () => {
        const params = {
          grant_type: 'authorization_code',
          code: 'c0de',
          redirect_uri: 'https://example.com/callback'
        }
        const req = { method: 'POST', body: params }
        const res = {}
        const host = {}
        const provider = { host, grant_types_supported: ['authorization_code'] }
        const request = new TokenRequest(req, res, provider)

        let thrownError

        try {
          request.validate()
        } catch (error) {
          thrownError = error
        }

        expect(thrownError).to.not.exist()
      })
    })

    describe('with missing grant_type parameter', () => {
      let params, req, res, host, provider, request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')
        params = {}
        req = { method: 'POST', body: params }
        res = {}
        host = {}
        provider = { host }
        request = new TokenRequest(req, res, provider)
        request.validate()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 bad request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Missing grant type'
        })
      })
    })

    describe('with unsupported grant type', () => {
      let params, req, res, host, provider, request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')
        params = { grant_type: 'unsupported' }
        req = { method: 'POST', body: params }
        res = {}
        host = {}
        provider = { host, grant_types_supported: ['authorization_code'] }
        request = new TokenRequest(req, res, provider)
        request.validate()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 bad request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unsupported_grant_type',
          error_description: 'Unsupported grant type'
        })
      })
    })

    describe('with missing authorization code', () => {
      let params, req, res, host, provider, request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')
        params = { grant_type: 'authorization_code' }
        req = { method: 'POST', body: params }
        res = {}
        host = {}
        provider = { host, grant_types_supported: ['authorization_code'] }
        request = new TokenRequest(req, res, provider)
        request.validate()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 bad request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Missing authorization code'
        })
      })
    })

    describe('with missing redirect uri', () => {
      let params, req, res, host, provider, request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')
        params = { grant_type: 'authorization_code', code: 'c0d3' }
        req = { method: 'POST', body: params }
        res = {}
        host = {}
        provider = { host, grant_types_supported: ['authorization_code'] }
        request = new TokenRequest(req, res, provider)
        request.validate()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 bad request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Missing redirect uri'
        })
      })
    })

    describe('with missing refresh token parameter', () => {
      let params, req, res, host, provider, request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')
        params = { grant_type: 'refresh_token' }
        req = { method: 'POST', body: params }
        res = {}
        host = {}
        provider = { host, grant_types_supported: ['refresh_token'] }
        request = new TokenRequest(req, res, provider)
        request.validate()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 bad request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Missing refresh token'
        })
      })
    })
  })

  /**
   * Authenticate Client
   */
  describe('authenticateClient', () => {
    describe('with invalid client assertion type', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        const params = {
          grant_type: 'client_credentials',
          client_assertion_type: 'type'
        }

        const req = {
          method: 'POST',
          body: params
        }

        const res = {}
        const host = {}
        const provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        return request.authenticateClient()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Invalid client assertion type'
        })
      })
    })

    describe('with missing client assertion', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        const params = {
          grant_type: 'client_credentials',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        }

        const req = {
          method: 'POST',
          body: params
        }

        const res = {}
        const host = {}
        const provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        return request.authenticateClient()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Missing client assertion'
        })
      })
    })

    describe('with missing client credentials', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        const params = {
          grant_type: 'client_credentials'
        }

        const req = {
          method: 'POST',
          body: params
        }

        const res = {}
        const host = {}
        const provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        return request.authenticateClient()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Missing client credentials'
        })
      })
    })

    describe('with well formed "client_secret_basic" credentials', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'clientSecretBasic')

        const params = {
          grant_type: 'client_credentials'
        }

        const req = {
          method: 'POST',
          body: params,
          headers: {
            authorization: 'Basic base64str'
          }
        }

        const res = {}
        const host = {}
        const provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        return request.authenticateClient()
      })

      after(() => {
        TokenRequest.prototype.clientSecretBasic.restore()
      })

      it('should invoke "client_secret_basic" authentication', () => {
        request.clientSecretBasic.should.have.been.called()
      })
    })

    describe('with well formed "client_secret_post" credentials', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'clientSecretPost')

        const params = {
          grant_type: 'client_credentials',
          client_id: 'uuid',
          client_secret: 's3cr3t'
        }

        const req = {
          method: 'POST',
          body: params
        }

        const res = {}
        const host = {}
        const provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        return request.authenticateClient()
      })

      after(() => {
        TokenRequest.prototype.clientSecretPost.restore()
      })

      it('should invoke "client_secret_post" authentication', () => {
        request.clientSecretPost.should.have.been.called()
      })
    })

    describe('with well formed "client_secret_jwt" credentials', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'clientSecretJWT')

        const params = {
          grant_type: 'client_credentials',
          client_assertion: 'jwt',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        }

        const req = {
          method: 'POST',
          body: params
        }

        const res = {}
        const host = {}
        const provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        return request.authenticateClient()
      })

      after(() => {
        TokenRequest.prototype.clientSecretJWT.restore()
      })

      it('should invoke "client_secret_jwt" authentication', () => {
        request.clientSecretJWT.should.have.been.called()
      })
    })
  })

  /**
   * Client Secret Basic
   */
  describe('clientSecretBasic', () => {
    describe('with malformed credentials', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        const req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: 'Basic MALFORMED'
          }
        }

        const res = {}
        const provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        return request.clientSecretBasic()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Malformed HTTP Basic credentials'
        })
      })
    })

    describe('with invalid authorization scheme', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        const req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: `Bearer ${Buffer.from('id:secret').toString('base64')}`
          }
        }

        const res = {}
        const provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        return request.clientSecretBasic()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Invalid authorization scheme'
        })
      })
    })

    describe('with missing credentials', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        const req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: `Basic ${Buffer.from(':').toString('base64')}`
          }
        }

        const res = {}
        const provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        return request.clientSecretBasic()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Missing client credentials'
        })
      })
    })

    describe('with unknown client', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'unauthorized')

        const req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: `Basic ${Buffer.from('id:secret').toString('base64')}`
          }
        }

        const res = {}
        const provider = {
          host: {},
          store: testStore()
        }

        request = new TokenRequest(req, res, provider)
        return request.clientSecretBasic()
      })

      after(() => {
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should respond "401 Unauthorized"', () => {
        request.unauthorized.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Unknown client identifier'
        })
      })
    })

    describe('with mismatching secret', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'unauthorized')

        const req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: `Basic ${Buffer.from('clientId:WRONG_SECRET').toString('base64')}`
          }
        }

        const res = {}
        const provider = {
          host: {},
          store: testStore()
        }

        await provider.store.clients.put('clientId', { client_secret: 'secret' })

        request = new TokenRequest(req, res, provider)
        return request.clientSecretBasic()
      })

      after(() => {
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should respond "401 Unauthorized"', () => {
        request.unauthorized.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Mismatching client secret'
        })
      })
    })

    describe('with valid credentials', () => {
      before(() => {
        sinon.stub(TokenRequest.prototype, 'unauthorized')
      })

      after(() => {
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should resolve request', async () => {
        const req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: `Basic ${Buffer.from('clientId:secret').toString('base64')}`
          }
        }

        const res = {}
        const client = { client_secret: 'secret' }
        const provider = {
          host: {},
          store: testStore()
        }
        await provider.store.clients.put('clientId', { client_secret: 'secret' })

        const request = new TokenRequest(req, res, provider)
        const loadedClient = await request.clientSecretBasic()

        expect(loadedClient).to.eql(client)
      })
    })
  })

  /**
   * Client Secret Post
   */
  describe('clientSecretPost', () => {
    describe('with missing client id', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        const req = {
          method: 'POST',
          body: {
            client_secret: 'secret'
          }
        }

        const res = {}
        const provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        return request.clientSecretPost()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Missing client credentials'
        })
      })
    })

    describe('with missing client secret', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        const req = {
          method: 'POST',
          body: {
            client_id: 'secret'
          }
        }

        const res = {}
        const provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        return request.clientSecretPost()
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Missing client credentials'
        })
      })
    })

    describe('with unknown client', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'unauthorized')

        const req = {
          method: 'POST',
          body: {
            client_id: 'uuid',
            client_secret: 'secret'
          }
        }

        const res = {}
        const provider = {
          host: {},
          store: testStore()
        }

        request = new TokenRequest(req, res, provider)
        return request.clientSecretPost()
      })

      after(() => {
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should respond "401 Unauthorized"', () => {
        request.unauthorized.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Unknown client identifier'
        })
      })
    })

    describe('with mismatching client secret', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'unauthorized')

        const req = {
          method: 'POST',
          body: {
            client_id: 'uuid',
            client_secret: 'WRONG'
          }
        }

        const res = {}
        const provider = {
          host: {},
          store: testStore()
        }

        await provider.store.clients.put('uuid', { client_secret: 'secret' })
        request = new TokenRequest(req, res, provider)
        return request.clientSecretPost()
      })

      after(() => {
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should respond "401 Unauthorized"', () => {
        request.unauthorized.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Mismatching client secret'
        })
      })
    })

    describe('with valid credentials', () => {
      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')
        sinon.stub(TokenRequest.prototype, 'unauthorized')
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should resolve request with client added', async () => {
        const client_id = 'uuid'
        const req = {
          method: 'POST',
          body: {
            client_id: client_id,
            client_secret: 'secret'
          }
        }

        const client = { client_id, client_secret: 'secret' }

        const res = {}
        const provider = {
          host: {},
          store: testStore()
        }
        await provider.store.clients.put(client_id, client)

        const request = new TokenRequest(req, res, provider)
        const loadedClient = await request.clientSecretPost()

        request.badRequest.should.not.have.been.called()
        request.unauthorized.should.not.have.been.called()

        expect(loadedClient).to.equal(client)
      })
    })
  })

  /**
   * Client Secret JWT
   */
  describe('clientSecretJWT', () => {})

  /**
   * Private Key JWT
   */
  describe('privateKeyJWT', () => {})

  /**
   * None
   */
  describe('none', () => {})

  /**
   * Grant
   */
  describe('grant', () => {
    describe('with "authorization_code" grant type', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'authorizationCodeGrant')

        const req = { method: 'POST', body: { grant_type: 'authorization_code' } }
        const res = {}
        const provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        return request.grant()
      })

      after(() => {
        TokenRequest.prototype.authorizationCodeGrant.restore()
      })

      it('should invoke authorizationCodeGrant', () => {
        request.authorizationCodeGrant.should.have.been.called()
      })
    })

    describe('with "refresh_token" grant type', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'refreshTokenGrant')

        const req = { method: 'POST', body: { grant_type: 'refresh_token' } }
        const res = {}
        const provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        return request.grant()
      })

      after(() => {
        TokenRequest.prototype.refreshTokenGrant.restore()
      })

      it('should invoke refreshTokenGrant', () => {
        request.refreshTokenGrant.should.have.been.called()
      })
    })

    describe('with "client_credentials" grant type', () => {
      let request

      before(async () => {
        sinon.stub(TokenRequest.prototype, 'clientCredentialsGrant')

        const req = { method: 'POST', body: { grant_type: 'client_credentials' } }
        const res = {}
        const provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        return request.grant()
      })

      after(() => {
        TokenRequest.prototype.clientCredentialsGrant.restore()
      })

      it('should invoke clientCredentialsGrant', () => {
        request.clientCredentialsGrant.should.have.been.called()
      })
    })

    describe('with unknown grant type', () => {
      let request

      before(() => {
        const req = { method: 'POST', body: { grant_type: 'noyoudint' } }
        const res = {}
        const provider = { host: {} }

        request = new TokenRequest(req, res, provider)
      })

      it('should throw and error', async () => {
        let thrownError

        try {
          await request.grant()
        } catch (error) {
          thrownError = error
        }
        expect(thrownError).to.exist()
        expect(thrownError.message).to.match(/Unsupported response type/)
      })
    })
  })

  /**
   * Authorization Code Grant
   */
  describe('authorizationCodeGrant', () => {
    let params, request, tokenResponse

    beforeEach(() => {
      tokenResponse = {}
      params = { grant_type: 'authorization_code' }
      const req = { method: 'POST', body: params }
      const res = {
        json: sinon.stub()
      }
      const provider = { host: {} }
      request = new TokenRequest(req, res, provider)

      request.includeAccessToken = sinon.stub().resolves(tokenResponse)
      request.includeIDToken = sinon.stub().resolves(tokenResponse)
    })

    it('should issue an access token', () => {
      return request.authorizationCodeGrant()
        .then(() => {
          expect(request.includeAccessToken).to.have.been.called()
        })
    })

    it('should issue an id token', () => {
      return request.authorizationCodeGrant()
        .then(() => {
          expect(request.includeIDToken).to.have.been.called()
        })
    })

    it('should send a response in json format', () => {
      return request.authorizationCodeGrant()
        .then(() => {
          expect(request.res.json).to.have.been.called()
        })
    })
  })

  /**
   * Refresh Token Grant
   */
  describe('refreshTokenGrant', () => {})

  /**
   * Client Credentials Grant
   */
  describe('clientCredentialsGrant', () => {
    let params, request
    const accessToken = 'accesst0ken'

    before(() => {
      sinon.stub(AccessToken, 'issueForRequest')
      AccessToken.issueForRequest.resolves(accessToken)
    })

    after(() => {
      AccessToken.issueForRequest.restore()
    })

    beforeEach(() => {
      params = { grant_type: 'authorization_code' }
      const req = { method: 'POST', body: params }
      const res = {
        json: sinon.stub(),
        set: sinon.stub()
      }
      const provider = { host: {} }
      request = new TokenRequest(req, res, provider)
      request.client = {}
    })

    it('should set the cache control response headers', () => {
      return request.clientCredentialsGrant()
        .then(() => {
          expect(request.res.set).to.have.been.calledWith({
            'Cache-Control': 'no-store',
            Pragma: 'no-cache'
          })
        })
    })

    it('should send the json response', () => {
      request.client.default_max_age = 3000

      return request.clientCredentialsGrant()
        .then(() => {
          expect(request.res.json).to.have.been.calledWith({
            access_token: 'accesst0ken', expires_in: 3000, token_type: 'Bearer'
          })
        })
    })

    it('should only set the expires_in property if applicable', () => {
      request.client.default_max_age = undefined

      return request.clientCredentialsGrant()
        .then(() => {
          expect(request.res.json).to.have.been.calledWith({
            access_token: 'accesst0ken', token_type: 'Bearer'
          })
        })
    })
  })

  /**
   * Verify Authorization Code
   */
  describe('verifyAuthorizationCode', () => {
    const code = 'c0de123'
    let request, provider, res, authCode

    beforeEach(async () => {
      const req = {
        method: 'POST',
        body: {
          code,
          client_id: 'uuid',
          client_secret: 'secret',
          grant_type: 'authorization_code',
          redirect_uri: 'https://app.com/callback'
        }
      }

      res = HttpMocks.createResponse()
      provider = {
        host: {},
        store: testStore()
      }

      authCode = {
        exp: Math.floor(Date.now() / 1000) + 1000,
        redirect_uri: 'https://app.com/callback',
        aud: 'client123'
      }

      await provider.store.codes.put(code, authCode)

      request = new TokenRequest(req, res, provider)

      request.client = {
        client_id: 'client123'
      }

      sinon.spy(request, 'badRequest')
    })

    it('should pass through the request if grant type is not authorization_code', async () => {
      request.grantType = 'something'

      const result = await request.verifyAuthorizationCode()
      expect(result).to.be.undefined()
    })

    it('should throw an error when no saved authorization code is found', async () => {
      Object.assign(provider.store, testStore())

      let thrownError
      try {
        await request.verifyAuthorizationCode()
      } catch (error) {
        thrownError = error
      }

      expect(thrownError.error).to.equal('invalid_grant')
      expect(thrownError.error_description).to.equal('Authorization not found')
      expect(request.badRequest).to.have.been.called()
    })

    it('should throw an error when the auth code was previously used', done => {
      authCode.used = true

      request.verifyAuthorizationCode()
        .catch(err => {
          expect(err.error).to.equal('invalid_grant')
          expect(err.error_description).to.equal('Authorization code invalid')
          expect(request.badRequest).to.have.been.called()
          done()
        })
    })

    it('should throw an error when the auth code is expired', done => {
      authCode.exp = Math.floor(Date.now() / 1000) - 1000

      request.verifyAuthorizationCode()
        .catch(err => {
          expect(err.error).to.equal('invalid_grant')
          expect(err.error_description).to.equal('Authorization code expired')
          expect(request.badRequest).to.have.been.called()
          done()
        })
    })

    it('should throw an error on redirect_uri mismatch', done => {
      authCode.redirect_uri = 'something'

      request.verifyAuthorizationCode()
        .catch(err => {
          expect(err.error).to.equal('invalid_grant')
          expect(err.error_description).to.equal('Mismatching redirect uri')
          expect(request.badRequest).to.have.been.called()
          done()
        })
    })

    it('should throw an error on mismatching client id', done => {
      authCode.aud = 'someOtherClient'

      request.verifyAuthorizationCode()
        .catch(err => {
          expect(err.error).to.equal('invalid_grant')
          expect(err.error_description).to.equal('Mismatching client id')
          expect(request.badRequest).to.have.been.called()
          done()
        })
    })

    it('should set the request code when successful', async () => {
      const result = await request.verifyAuthorizationCode()
      expect(result).to.equal(authCode)
    })
  })

  /**
   * Include Access Token
   */
  describe('includeAccessToken', () => {
    let params, request, tokenResponse

    beforeEach(() => {
      tokenResponse = {}
      params = { grant_type: 'authorization_code' }
      const req = { method: 'POST', body: params }
      const res = {}
      const provider = { host: {} }
      request = new TokenRequest(req, res, provider)

      sinon.stub(AccessToken, 'issueForRequest')
      AccessToken.issueForRequest.resolves()
    })

    after(() => {
      AccessToken.issueForRequest.restore()
    })

    it('should issue an access token', async () => {
      await request.includeAccessToken(tokenResponse)
      expect(AccessToken.issueForRequest).to.have.been
        .calledWith(request, tokenResponse)
    })
  })

  /**
   * Include Refresh Token
   */
  describe('includeRefreshToken', () => {})

  /**
   * Include ID Token
   */
  describe('includeIDToken', () => {
    let params, request, tokenResponse

    before(() => {
      tokenResponse = {}
      params = { grant_type: 'authorization_code' }
      const req = { method: 'POST', body: params }
      const res = {}
      const provider = { host: {} }
      request = new TokenRequest(req, res, provider)

      sinon.stub(IDToken, 'issueForRequest')
      IDToken.issueForRequest.resolves()
    })

    after(() => {
      IDToken.issueForRequest.restore()
    })

    it('should issue an id token', () => {
      return request.includeIDToken(tokenResponse)
        .then(() => {
          expect(IDToken.issueForRequest).to.have.been
            .calledWith(request, tokenResponse)
        })
    })
  })
})
