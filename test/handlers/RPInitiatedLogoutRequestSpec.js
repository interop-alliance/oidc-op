'use strict'

const chai = require('chai')
const expect = chai.expect
// const sinon = require('sinon')
const sinonChai = require('sinon-chai')
chai.use(require('dirty-chai'))
chai.use(sinonChai)
chai.should()
const HttpMocks = require('node-mocks-http')

const RPInitiatedLogoutRequest = require('../../src/handlers/RPInitiatedLogoutRequest')
// const IDToken = require('../../src/IDToken')

const provider = {
  host: {
    defaults: {
      post_logout_redirect_uri: '/goodbye'
    }
  }
}

// async function issueIdToken (oidcProvider) {
//   const jwt = IDToken.issue(oidcProvider, {
//     sub: 'user123',
//     aud: 'https://op.example.com',
//     azp: 'client123'
//   })
//
//   return jwt.encode()
// }

const postLogoutRedirectUri = 'https://rp.example.com/goodbye'
const reqNoParams = HttpMocks.createRequest({ method: 'GET', params: {} })
const reqWithParams = HttpMocks.createRequest({
  method: 'GET',
  query: {
    id_token_hint: {},
    state: 'abc123',
    post_logout_redirect_uri: postLogoutRedirectUri
  }
})

describe('RPInitiatedLogoutRequest', () => {
  describe('constructor()', () => {
    it('should parse the incoming request params', () => {
      const res = {}
      const request = new RPInitiatedLogoutRequest(reqWithParams, res, provider)

      expect(request).to.have.property('params')
      expect(Object.keys(request.params).length).to.equal(3)
      expect(request.params.state).to.equal('abc123')
    })
  })

  describe('validate()', () => {
    it('should validate the `id_token_hint` param')
    it('should validate that `post_logout_redirect_uri` has been registered')
  })

  describe('redirectToPostLogoutUri()', () => {
    it('should redirect to RP if logout uri provided', () => {
      const res = HttpMocks.createResponse()
      const req = HttpMocks.createRequest({
        method: 'GET',
        query: {
          post_logout_redirect_uri: postLogoutRedirectUri,
          state: '$tate'
        }
      })
      const request = new RPInitiatedLogoutRequest(req, res, provider)

      request.redirectToPostLogoutUri()

      expect(res.statusCode).to.equal(302)
      expect(res._getRedirectUrl())
        .to.equal(postLogoutRedirectUri + '?state=%24tate')
    })

    it('should redirect to host default if no RP logout uri provided', () => {
      const res = HttpMocks.createResponse()
      const request = new RPInitiatedLogoutRequest(reqNoParams, res, provider)

      request.redirectToPostLogoutUri()

      expect(res.statusCode).to.equal(302)
      expect(res._getRedirectUrl())
        .to.equal(provider.host.defaults.post_logout_redirect_uri)
    })
  })
})
