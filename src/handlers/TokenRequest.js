'use strict'

/**
 * Dependencies
 * @ignore
 */
const BaseRequest = require('./BaseRequest')
const AccessToken = require('../AccessToken')
// const AuthorizationCode = require('../AuthorizationCode')
const IDToken = require('../IDToken')
const { JWT } = require('@solid/jose')
const base64url = require('base64url')

/**
 * TokenRequest
 */
class TokenRequest extends BaseRequest {
  /**
   * Request Handler
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   * @param {Provider} provider
   */
  static async handle (req, res, provider) {
    let request
    try {
      request = new TokenRequest(req, res, provider)
      request.validate()
      request.param = await request.decodeRequestParam()
      request.client = await request.authenticateClient()
      request.code = await request.verifyAuthorizationCode()
      return request.grant()
    } catch (error) {
      request.error(error)
    }
  }

  /**
   * Constructor
   */
  constructor (req, res, provider) {
    super(req, res, provider)
    this.params = TokenRequest.getParams(this)
    this.grantType = TokenRequest.getGrantType(this)
  }

  /**
   * Get Grant Type
   *
   * @param {TokenRequest} request
   * @return {string}
   */
  static getGrantType (request) {
    const { params } = request
    return params.grant_type
  }

  /**
   * Validate Request
   */
  validate () {
    const { params } = this

    // MISSING GRANT TYPE
    if (!params.grant_type) {
      return this.badRequest({
        error: 'invalid_request',
        error_description: 'Missing grant type'
      })
    }

    // UNSUPPORTED GRANT TYPE
    if (!this.supportedGrantType()) {
      return this.badRequest({
        error: 'unsupported_grant_type',
        error_description: 'Unsupported grant type'
      })
    }

    // MISSING AUTHORIZATION CODE
    if (params.grant_type === 'authorization_code' && !params.code) {
      return this.badRequest({
        error: 'invalid_request',
        error_description: 'Missing authorization code'
      })
    }

    // MISSING REDIRECT URI
    if (params.grant_type === 'authorization_code' && !params.redirect_uri) {
      return this.badRequest({
        error: 'invalid_request',
        error_description: 'Missing redirect uri'
      })
    }

    // MISSING REFRESH TOKEN
    if (params.grant_type === 'refresh_token' && !params.refresh_token) {
      return this.badRequest({
        error: 'invalid_request',
        error_description: 'Missing refresh token'
      })
    }
  }

  /**
   * Supported Grant Type
   * @returns {Boolean}
   */
  supportedGrantType () {
    const { params, provider } = this
    const supportedGrantTypes = provider.grant_types_supported
    const requestedGrantType = params.grant_type

    return supportedGrantTypes.includes(requestedGrantType)
  }

  /**
   * Authenticate Client
   *
   * @param request {TokenRequest}
   * @returns {Promise<Client>}
   */
  async authenticateClient () {
    const { req } = this

    // Use HTTP Basic Authentication Method
    if (req.headers && req.headers.authorization) {
      return this.clientSecretBasic()
    }

    // Use HTTP Post Authentication Method
    if (req.body && req.body.client_secret) {
      return this.clientSecretPost()
    }

    // Use Client JWT Authentication Method
    if (req.body && req.body.client_assertion_type) {
      const type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

      // Invalid client assertion type
      if (req.body.client_assertion_type !== type) {
        return this.badRequest({
          error: 'unauthorized_client',
          error_description: 'Invalid client assertion type'
        })
      }

      // Missing client assertion
      if (!req.body.client_assertion) {
        return this.badRequest({
          error: 'unauthorized_client',
          error_description: 'Missing client assertion'
        })
      }

      return this.clientSecretJWT()
    }

    // Missing authentication parameters
    return this.badRequest({
      error: 'unauthorized_client',
      error_description: 'Missing client credentials'
    })
  }

  /**
   * Client Secret Basic Authentication
   *
   * @description
   * HTTP Basic Authentication of client using client_id and client_secret as
   * username and password.
   * @returns {Promise<Client>}
   */
  async clientSecretBasic () {
    const { req: { headers }, provider } = this
    const authorization = headers.authorization.split(' ')
    const scheme = authorization[0]
    const credentials = Buffer.from(authorization[1], 'base64')
      .toString('ascii')
      .split(':')
    const [id, secret] = credentials

    // MALFORMED CREDENTIALS
    if (credentials.length !== 2) {
      return this.badRequest({
        error: 'unauthorized_client',
        error_description: 'Malformed HTTP Basic credentials'
      })
    }

    // INVALID AUTHORIZATION SCHEME
    if (!/^Basic$/i.test(scheme)) {
      return this.badRequest({
        error: 'unauthorized_client',
        error_description: 'Invalid authorization scheme'
      })
    }

    // MISSING CREDENTIALS
    if (!id || !secret) {
      return this.badRequest({
        error: 'unauthorized_client',
        error_description: 'Missing client credentials'
      })
    }

    const client = await provider.store.clients.get(id)
    // UNKNOWN CLIENT
    if (!client) {
      return this.unauthorized({
        error: 'unauthorized_client',
        error_description: 'Unknown client identifier'
      })
    }

    // MISMATCHING SECRET
    if (client.client_secret !== secret) {
      return this.unauthorized({
        error: 'unauthorized_client',
        error_description: 'Mismatching client secret'
      })
    }

    return client
  }

  /**
   * Client Secret Post
   *
   * @description
   * Authentication of client using client_id and client_secret as HTTP POST
   * body parameters.
   * @returns {Promise<Client>}
   */
  async clientSecretPost () {
    const { params: { client_id: id, client_secret: secret }, provider } = this

    // MISSING CREDENTIALS
    if (!id || !secret) {
      return this.badRequest({
        error: 'unauthorized_client',
        error_description: 'Missing client credentials'
      })
    }

    const client = await provider.store.clients.get(id)
    // UNKNOWN CLIENT
    if (!client) {
      return this.unauthorized({
        error: 'unauthorized_client',
        error_description: 'Unknown client identifier'
      })
    }

    // MISMATCHING SECRET
    if (client.client_secret !== secret) {
      return this.unauthorized({
        error: 'unauthorized_client',
        error_description: 'Mismatching client secret'
      })
    }

    return client
  }

  /**
   * Client Secret JWT Authentication
   *
   * TODO RTFS
   * @returns {Promise<Client>}
   */
  async clientSecretJWT () {
    const { req: { body: { client_assertion: jwt } }, provider } = this
    const payloadB64u = jwt.split('.')[1]
    const payload = JSON.parse(base64url.decode(payloadB64u))

    if (!payload || !payload.sub) {
      return this.badRequest({
        error: 'unauthorized_client',
        error_description: 'Cannot extract client id from JWT'
      })
    }

    const client = await provider.store.clients.get(payload.sub)
    if (!client) {
      return this.badRequest({
        error: 'unauthorized_client',
        error_description: 'Unknown client'
      })
    }

    if (!client.client_secret) {
      return this.badRequest({
        error: 'unauthorized_client',
        error_description: 'Missing client secret'
      })
    }

    const token = JWT.decode(jwt, client.client_secret)

    if (!token || token instanceof Error) {
      return this.badRequest({
        error: 'unauthorized_client',
        error_description: 'Invalid client JWT'
      })
    }

    // TODO validate the payload
    return client
  }

  /**
   * Private Key JWT Authentication
   */
  // privateKeyJWT () {}

  /**
   * None Authentication
   */
  // none () {}

  /**
   * Grant
   *
   * @returns {Promise<Null>}
   */
  async grant () {
    const { grantType } = this

    if (grantType === 'authorization_code') {
      return this.authorizationCodeGrant()
    }

    if (grantType === 'refresh_token') {
      return this.refreshTokenGrant()
    }

    if (grantType === 'client_credentials') {
      return this.clientCredentialsGrant()
    }

    // THIS IS SERIOUS TROUBLE
    // REQUEST VALIDATION SHOULD FILTER OUT
    // UNSUPPORTED GRANT TYPES BEFORE WE ARRIVE
    // HERE.
    throw new Error('Unsupported response type')
  }

  /**
   * Authorization Code Grant
   * @returns {Promise<Null>}
   */
  async authorizationCodeGrant () {
    let response = {}
    response = await this.includeAccessToken(response)
    response = await this.includeIDToken(response)

    this.res.json(response)
  }

  /**
   * includeAccessToken
   */
  async includeAccessToken (response) {
    return AccessToken.issueForRequest(this, response)
  }

  /**
   * includeIDToken
   */
  async includeIDToken (response) {
    return IDToken.issueForRequest(this, response)
  }

  /**
   * Refresh Grant
   *
   * @param {TokenRequest} request
   * @returns {Promise<Object>} Resolves to response object
   */
  refreshTokenGrant (request) {
    // return AccessToken.refresh(request).then(this.tokenResponse)
    throw new Error('refreshTokenGrant not implemented.')
  }

  /**
   * OAuth 2.0 Client Credentials Grant
   *
   * @param {TokenRequest} request
   * @returns {Promise<Null>}
   */
  async clientCredentialsGrant () {
    const { res, client: { default_max_age: expires } } = this

    const token = await AccessToken.issueForRequest(this, res)
    const response = {}

    res.set({
      'Cache-Control': 'no-store',
      Pragma: 'no-cache'
    })

    response.access_token = token
    response.token_type = 'Bearer'
    if (expires) {
      response.expires_in = expires
    }

    res.json(response)
  }

  /**
   * @returns {Promise<object>} Decoded params, with `request` jwt payload
   */
  async decodeRequestParam () {
    const { params } = this

    if (!params.request) {
      return // Pass through, no request param present
    }

    let requestJwt

    try {
      requestJwt = JWT.decode(params.request)
    } catch (error) {
      this.redirect({
        error: 'invalid_request_object',
        error_description: error.message
      })
    }

    try {
      if (requestJwt.payload.key) {
        await this.loadCnfKey(requestJwt.payload.key)
      }
    } catch (error) {
      this.redirect({
        error: 'invalid_request_object',
        error_description: 'Error importing cnf key: ' + error.message
      })
    }

    await this.validateRequestParam(requestJwt)

    return Object.assign({}, params, requestJwt.payload)
  }

  /**
   * Verify Authorization Code
   * @returns {string} Authorization code
   */
  async verifyAuthorizationCode () {
    const { params, client, provider, grantType } = this

    if (grantType !== 'authorization_code') {
      return
    }

    const authorizationCode = await provider.store.codes.get(params.code)

    // UNKNOWN AUTHORIZATION CODE
    if (!authorizationCode) {
      return this.badRequest({
        error: 'invalid_grant',
        error_description: 'Authorization not found'
      })
    }

    // AUTHORIZATION CODE HAS BEEN PREVIOUSLY USED
    if (authorizationCode.used === true) {
      return this.badRequest({
        error: 'invalid_grant',
        error_description: 'Authorization code invalid'
      })
    }

    // AUTHORIZATION CODE IS EXPIRED
    if (authorizationCode.exp < Math.floor(Date.now() / 1000)) {
      return this.badRequest({
        error: 'invalid_grant',
        error_description: 'Authorization code expired'
      })
    }

    // MISMATCHING REDIRECT URI
    if (authorizationCode.redirect_uri !== params.redirect_uri) {
      return this.badRequest({
        error: 'invalid_grant',
        error_description: 'Mismatching redirect uri'
      })
    }

    // MISMATCHING CLIENT ID
    if (authorizationCode.aud !== client.client_id) {
      return this.badRequest({
        error: 'invalid_grant',
        error_description: 'Mismatching client id'
      })
    }

    // TODO mismatching user id?

    // TODO UPDATE AUTHORIZATION CODE TO REFLECT THAT IT'S BEEN USED
    // authorizationCode.use()

    return authorizationCode
  }

  async validateRequestParam (requestJwt) {
    const { params } = this
    const { payload } = requestJwt

    // request and request_uri parameters MUST NOT be included in Request Objects
    if (payload.request) {
      return this.redirect({
        error: 'invalid_request_object',
        error_description: 'Illegal request claim in payload'
      })
    }
    if (payload.request_uri) {
      return this.redirect({
        error: 'invalid_request_object',
        error_description: 'Illegal request_uri claim in payload'
      })
    }

    // So that the request is a valid OAuth 2.0 Authorization Request, values
    // for the response_type and client_id parameters MUST be included using
    // the OAuth 2.0 request syntax, since they are REQUIRED by OAuth 2.0.
    // The values for these parameters MUST match those in the Request Object,
    // if present.
    if (payload.client_id && payload.client_id !== params.client_id) {
      return this.forbidden({
        error: 'unauthorized_client',
        error_description: 'Mismatching client id in request object'
      })
    }

    if (payload.response_type && payload.response_type !== params.response_type) {
      return this.redirect({
        error: 'invalid_request',
        error_description: 'Mismatching response type in request object'
      })
    }

    // Even if a scope parameter is present in the Request Object value, a scope
    // parameter MUST always be passed using the OAuth 2.0 request syntax
    // containing the openid scope value to indicate to the underlying OAuth 2.0
    // logic that this is an OpenID Connect request.
    if (payload.scope && payload.scope !== params.scope) {
      return this.redirect({
        error: 'invalid_scope',
        error_description: 'Mismatching scope in request object'
      })
    }

    // TODO: What to do with this? SHOULD considered harmful, indeed...
    // If signed, the Request Object SHOULD contain the Claims iss
    // (issuer) and aud (audience) as members. The iss value SHOULD be the
    // Client ID of the RP, unless it was signed by a different party than the
    // RP. The aud value SHOULD be or include the OP's Issuer Identifier URL.

    await this.validateRequestParamSignature(requestJwt)
  }

  /**
   * validateRequestParamSignature
   *
   * @param requestJwt {JWT} Decoded request object
   *
   * @returns {Promise}
   */
  async validateRequestParamSignature (requestJwt) {
    // From https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

    // request_object_signing_alg
    //   OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing
    //   Request Objects sent to the OP. All Request Objects from this Client
    //   MUST be rejected, if not signed with this algorithm. Request Objects
    //   are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core].
    //   This algorithm MUST be used both when the Request Object is passed by
    //   value (using the request parameter) and when it is passed by reference
    //   (using the request_uri parameter). Servers SHOULD support RS256.
    //   The value none MAY be used. The default, if omitted, is that any
    //   algorithm supported by the OP and the RP MAY be used.

    // From https://openid.net/specs/openid-connect-core-1_0.html#SignedRequestObject

    // The Request Object MAY be signed or unsigned (plaintext). When it is
    // plaintext, this is indicated by use of the none algorithm [JWA] in the
    // JOSE Header.

    // For Signature Validation, the alg Header Parameter in the JOSE Header
    // MUST match the value of the request_object_signing_alg set during Client
    // Registration or a value that was pre-registered by
    // other means. The signature MUST be validated against the appropriate key
    // for that client_id and algorithm.

    if (!this.client) {
      // No client_id, or no registration found for it
      // An error will be thrown downstream in `validate()`
      return
    }

    const clientJwks = this.client.jwks
    const registeredSigningAlg = this.client.request_object_signing_alg

    const signedRequest = requestJwt.header.alg !== 'none'
    const signatureRequired = clientJwks ||
      (registeredSigningAlg && registeredSigningAlg !== 'none')

    if (!signedRequest && !signatureRequired) {
      // Unsigned, signature not required - ok
      return
    }

    if (signedRequest && !clientJwks) {
      // No keys pre-registered, but the request is signed. Throw error
      return this.redirect({
        error: 'invalid_request',
        error_description: 'Signed request object, but no jwks pre-registered'
      })
    }

    if (signedRequest && registeredSigningAlg === 'none') {
      return this.redirect({
        error: 'invalid_request',
        error_description: 'Signed request object, but no signature allowed by request_object_signing_alg'
      })
    }

    if (!signedRequest && signatureRequired) {
      return this.redirect({
        error: 'invalid_request',
        error_description: 'Signature required for request object'
      })
    }

    if (registeredSigningAlg && requestJwt.header.alg !== registeredSigningAlg) {
      return this.redirect({
        error: 'invalid_request',
        error_description: 'Request signed by algorithm that does not match registered request_object_signing_alg value'
      })
    }

    // Request is signed. Validate signature against registered jwks
    const keyMatch = requestJwt.resolveKeys(clientJwks)

    if (!keyMatch) {
      return this.redirect({
        error: 'invalid_request',
        error_description: 'Cannot resolve signing key for request object'
      })
    }

    const verified = await requestJwt.verify()

    if (!verified) {
      return this.redirect({
        error: 'invalid_request',
        error_description: 'Invalid request object signature'
      })
    }
  }
}

/**
 * Export
 */
module.exports = TokenRequest
