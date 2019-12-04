'use strict'

/**
 * Test dependencies
 */
const fs = require('fs')
const path = require('path')
const chai = require('chai')
const HttpMocks = require('node-mocks-http')

/**
 * Assertions
 */
const sinon = require('sinon')
chai.use(require('dirty-chai'))
chai.use(require('sinon-chai'))
chai.should()
const expect = chai.expect

/**
 * Code under test
 */
const Provider = require('../../src/Provider')
const Client = require('../../src/Client')
const DynamicRegistrationRequest = require('../../src/handlers/DynamicRegistrationRequest')
const testStore = require('../test-storage')

/**
 * Tests
 */
describe('DynamicRegistrationRequest', () => {
  const defaultRsUri = 'https://rs.example.com'
  let req, res, provider
  let request

  before(() => {
    const configPath = path.join(__dirname, '..', 'config', 'provider.json')

    const storedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'))
    storedConfig.serverUri = defaultRsUri
    storedConfig.store = testStore()

    provider = new Provider(storedConfig)

    return provider.initializeKeyChain(provider.keys)
  })

  beforeEach(() => {
    req = HttpMocks.createRequest({
      body: {
        client_id: 'https://app.example.com',
        redirect_uris: ['https://app.example.com/callback']
      }
    })
    res = HttpMocks.createResponse()

    Object.assign(provider.store, testStore())

    request = new DynamicRegistrationRequest(req, res, provider)
    sinon.spy(request, 'badRequest')
  })

  describe('initRegistration', () => {
    it('should throw an error on missing registration', () => {
      request.req.body = undefined

      let thrownError

      try {
        request.initRegistration()
      } catch (error) {
        thrownError = error
      }

      expect(thrownError.error_description)
        .to.equal('Missing registration request body')
      expect(request.badRequest).to.have.been.called()
    })

    it('should throw an error on missing redirect_uris', () => {
      request.req.body.redirect_uris = undefined

      let thrownError

      try {
        request.initRegistration()
      } catch (error) {
        thrownError = error
      }
      expect(thrownError.error_description)
        .to.equal('Missing redirect_uris parameter')
      expect(request.badRequest).to.have.been.called()
    })

    it('should generate a client_id if one is not provided', () => {
      request.req.body.client_id = undefined
      request.req.body.response_types = ['id_token token']
      sinon.spy(request, 'identifier')

      const registration = request.initRegistration()

      expect(request.identifier).to.have.been.called()
      expect(registration.client_id).to.exist()
    })

    it('should generate a client_secret for non-implicit requests', () => {
      request.req.body.response_types = ['code']

      sinon.spy(request, 'secret')

      const registration = request.initRegistration()

      expect(request.secret).to.have.been.called()
      expect(registration.client_secret).to.exist()
    })
  })

  describe('initClient', () => {
    it('should return the initialized client', () => {
      const client = request.initClient({
        client_id: 'https://app.example.com',
        redirect_uris: ['https://app.example.com/callback']
      })

      expect(client).to.be.an.instanceof(Client)
    })
  })

  describe('register', () => {
    it('should store a registered client in the clients collection', async () => {
      const client = { client_id: 'client123' }

      request.client = client

      await request.register()
      const storedClient = await provider.store.clients.get('client123')
      expect(storedClient).to.eql(client)
    })
  })

  describe('token', () => {
    it('should create an access token', async () => {
      const registration = request.initRegistration()
      request.client = request.initClient(registration)
      const token = await request.token()

      expect(token.split('.').length).to.equal(3) // is a JWT
    })
  })

  describe('respond', () => {
    beforeEach(() => {
      request.client = {
        client_id: 'https://app.example.com'
      }
      request.compact = 't0ken'
    })

    it('responds with a 201 status code', () => {
      request.respond()

      expect(res._getStatusCode()).to.equal(201)
    })

    it('sets cache control response headers', () => {
      request.respond()

      const headers = res._getHeaders()

      expect(headers['cache-control']).to.equal('no-store')
      expect(headers.pragma).to.equal('no-cache')
    })

    it('responds with a client registration object', () => {
      request.respond()

      const registration = JSON.parse(res._getData())

      expect(registration.registration_access_token).to.equal('t0ken')
      expect(registration.registration_client_uri)
        .to.equal('https://example.com/register/https%3A%2F%2Fapp.example.com')
      expect(registration).to.have.property('client_id_issued_at')
    })

    it('sets the client_secret_expires_at property if applicable', () => {
      request.client.client_secret = 's33cret'

      request.respond()

      const registration = JSON.parse(res._getData())

      expect(registration.client_secret_expires_at).to.equal(0)
    })
  })

  describe('static handle', () => {
    it('performs dynamic registration', () => {
      return DynamicRegistrationRequest.handle(req, res, provider)
        .then(response => {
          expect(res._getStatusCode()).to.equal(201)
          const registration = JSON.parse(res._getData())

          expect(registration.registration_access_token).to.exist()
          expect(registration.response_types).to.eql(['code'])
        })
    })
  })
})
