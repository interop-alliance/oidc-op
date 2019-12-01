'use strict'

/**
 * Test dependencies
 */
const cwd = process.cwd()
const path = require('path')
const chai = require('chai')
const sinon = require('sinon')
const sinonChai = require('sinon-chai')

/**
 * Assertions
 */
chai.use(sinonChai)
chai.should()
const expect = chai.expect

/**
 * Code under test
 */
const BaseRequest = require(path.join(cwd, 'src', 'handlers', 'BaseRequest'))

/**
 * Tests
 */
describe('BaseRequest', () => {
  /**
   * Handle
   */
  describe('handle', () => {
    it('should throw an error', () => {
      expect(() => BaseRequest.handle())
        .to.throw(/Handle must be implemented by BaseRequest subclass/)
    })
  })

  /**
   * Constructor
   */
  describe('constructor', () => {
    let params, req, res, host, provider

    before(() => {
      params = { response_type: 'code' }
      req = { method: 'GET', query: params }
      res = {}
      host = {}
      provider = { host, serverUri: 'https://rs.example.com' }
    })

    it('should set "req"', () => {
      const request = new BaseRequest(req, res, provider)
      request.req.should.equal(req)
    })

    it('should set "res"', () => {
      const request = new BaseRequest(req, res, provider)
      request.res.should.equal(res)
    })

    it('should set "provider"', () => {
      const request = new BaseRequest(req, res, provider)
      request.provider.should.equal(provider)
    })

    it('should set "defaultRsUri"', () => {
      const request = new BaseRequest(req, res, provider)
      request.defaultRsUri.should.equal('https://rs.example.com')
    })

    it('should set "host"', () => {
      const request = new BaseRequest(req, res, provider)
      request.host.should.equal(host)
    })
  })

  /**
   * Get Params
   */
  describe('getParams', () => {
    it('should return GET request parameters', () => {
      const req = { method: 'GET', query: {} }
      const res = {}
      const provider = { host: {} }
      const request = new BaseRequest(req, res, provider)
      BaseRequest.getParams(request).should.equal(req.query)
    })

    it('should return POST request parameters', () => {
      const req = { method: 'POST', body: {} }
      const res = {}
      const provider = { host: {} }
      const request = new BaseRequest(req, res, provider)
      BaseRequest.getParams(request).should.equal(req.body)
    })
  })

  /**
   * Get Response Types
   */
  describe('getResponseTypes', () => {
    it('should create an array of response types', () => {
      const req = {}
      const res = {}
      const provider = { host: {} }

      const request = new BaseRequest(req, res, provider)
      request.params = { response_type: 'code id_token token' }

      BaseRequest.getResponseTypes(request).should.eql([
        'code',
        'id_token',
        'token'
      ])
    })
  })

  /**
   * Get Response Mode
   */
  describe('getResponseMode', () => {
    it('should return "?" for "query" response mode', () => {
      BaseRequest.getResponseMode({
        params: {
          response_mode: 'query'
        }
      }).should.equal('?')
    })

    it('should return "#" for "fragment" response mode', () => {
      BaseRequest.getResponseMode({
        params: {
          response_mode: 'fragment'
        }
      }).should.equal('#')
    })

    it('should return "?" for "code" response type', () => {
      BaseRequest.getResponseMode({
        params: {
          response_type: 'code'
        }
      }).should.equal('?')
    })

    it('should return "?" for "none" response type', () => {
      BaseRequest.getResponseMode({
        params: {
          response_type: 'none'
        }
      }).should.equal('?')
    })

    it('should return "#" for other response types', () => {
      BaseRequest.getResponseMode({
        params: {
          response_type: 'id_token token'
        }
      }).should.equal('#')
    })
  })

  describe('responseUri', () => {
    const data = {
      id_token: 't0ken',
      state: 'state123'
    }

    describe('hash fragment mode', () => {
      const responseMode = '#'

      it('should serialize response params in the hash fragment', () => {
        const uri = 'https://ex.com/resource'

        const result = BaseRequest.responseUri(uri, data, responseMode)

        expect(result).to
          .equal('https://ex.com/resource#id_token=t0ken&state=state123')
      })

      it('should preserve existing hash fragment', () => {
        const uri = 'https://ex.com/resource#hashFragment'

        const result = BaseRequest.responseUri(uri, data, responseMode)

        expect(result).to
          .equal('https://ex.com/resource#hashFragment&id_token=t0ken&state=state123')
      })
    })

    describe('query mode', () => {
      const responseMode = '?'

      it('should serialize response params in the search string', () => {
        const uri = 'https://ex.com/resource'

        const result = BaseRequest.responseUri(uri, data, responseMode)

        expect(result).to
          .equal('https://ex.com/resource?id_token=t0ken&state=state123')
      })

      it('should preserve existing query string', () => {
        const uri = 'https://ex.com/resource?key=value'

        const result = BaseRequest.responseUri(uri, data, responseMode)

        expect(result).to
          .equal('https://ex.com/resource?key=value&id_token=t0ken&state=state123')
      })
    })
  })

  /**
   * Redirect
   */
  describe('redirect', () => {
    it('should redirect with an authorization response', () => {
      const req = {
        method: 'GET',
        query: { redirect_uri: 'https://example.com/callback' }
      }

      const res = { redirect: sinon.spy() }
      const provider = { host: {} }
      const response = { foo: 'bar' }
      const request = new BaseRequest(req, res, provider)

      request.params = req.query
      request.responseMode = '#'
      try {
        request.redirect(response)
      } catch (error) {
        res.redirect.should.have.been
          .calledWith('https://example.com/callback#foo=bar')
      }
    })
  })

  /**
   * Unauthorized
   */
  describe('unauthorized', () => {
    let status, send, set

    beforeEach(() => {
      set = sinon.spy()
      send = sinon.spy()
      status = sinon.stub().returns({ send })

      const req = { method: 'GET', query: {} }
      const res = { set, status }
      const provider = { host: {} }
      const request = new BaseRequest(req, res, provider)

      try {
        request.unauthorized({
          realm: 'a',
          error: 'b',
          error_description: 'c'
        })
      } catch (error) {}
    })

    it('should respond 401', () => {
      status.should.have.been.calledWith(401)
    })

    it('should respond Unauthorized', () => {
      send.should.have.been.calledWith('Unauthorized')
    })

    it('should set WWW-Authenticate header', () => {
      set.should.have.been.calledWith({
        'WWW-Authenticate': 'Bearer realm=a, error=b, error_description=c'
      })
    })
  })

  /**
   * Forbidden
   */
  describe('forbidden', () => {
    let status, send

    beforeEach(() => {
      send = sinon.spy()
      status = sinon.stub().returns({ send })

      const req = { method: 'GET', query: {} }
      const res = { status }
      const provider = { host: {} }
      const request = new BaseRequest(req, res, provider)

      try {
        request.forbidden()
      } catch (error) {}
    })

    it('should respond 403', () => {
      status.should.have.been.calledWith(403)
    })

    it('should respond Forbidden', () => {
      send.should.have.been.calledWith('Forbidden')
    })
  })

  /**
   * Bad Request
   */
  describe('badRequest', () => {
    let status, json, set, err

    beforeEach(() => {
      set = sinon.spy()
      json = sinon.spy()
      status = sinon.stub().returns({ json })
      err = { error: 'error_name', error_description: 'description' }

      const req = { method: 'GET', query: {} }
      const res = { set, status }
      const provider = { host: {} }
      const request = new BaseRequest(req, res, provider)

      try {
        request.badRequest(err)
      } catch (error) {}
    })

    it('should respond 400', () => {
      status.should.have.been.calledWith(400)
    })

    it('should respond with JSON', () => {
      json.should.have.been.calledWith(err)
    })

    it('should set Cache-Control header', () => {
      set.should.have.been.calledWith(sinon.match({
        'Cache-Control': 'no-store'
      }))
    })

    it('should set Pragma header', () => {
      set.should.have.been.calledWith(sinon.match({
        Pragma: 'no-cache'
      }))
    })
  })

  /**
   * Internal Server Error
   */
  describe('internalServerError', () => {
    let status, send

    beforeEach(() => {
      send = sinon.spy()
      status = sinon.stub().returns({ send })

      const req = { method: 'GET', query: {} }
      const res = { status }
      const provider = { host: {} }
      const request = new BaseRequest(req, res, provider)

      request.internalServerError()
    })

    it('should respond 500', () => {
      status.should.have.been.calledWith(500)
    })

    it('should respond Internal Server Error', () => {
      send.should.have.been.called()
    })
  })
})
