'use strict'

/**
 * Dependencies
 * @ignore
 */
const BaseRequest = require('./BaseRequest')
const AccessToken = require('../AccessToken')
const AuthorizationCode = require('../AuthorizationCode')
const IDToken = require('../IDToken')
const { JWT, JWK, JWKSet } = require('@solid/jose')

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
  static handle (req, res, provider) {
    const request = new TokenRequest(req, res, provider)

    Promise
      .resolve(request)
      .then(request.validate)
      .then(request.decodeRequestParam)
      .then(request.authenticateClient)
      .then(request.verifyAuthorizationCode)
      .then(request.grant)
      .catch(err => request.error(err))
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
    const {params} = request
    return params.grant_type
  }

  /**
   * Validate Request
   *
   * @param request {TokenRequest}
   * @returns {Promise<TokenRequest>}
   */
  validate (request) {
    const {params} = request

    // MISSING GRANT TYPE
    if (!params.grant_type) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing grant type'
      })
    }

    // UNSUPPORTED GRANT TYPE
    if (!request.supportedGrantType()) {
      return request.badRequest({
        error: 'unsupported_grant_type',
        error_description: 'Unsupported grant type'
      })
    }

    // MISSING AUTHORIZATION CODE
    if (params.grant_type === 'authorization_code' && !params.code) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing authorization code'
      })
    }

    // MISSING REDIRECT URI
    if (params.grant_type === 'authorization_code' && !params.redirect_uri) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing redirect uri'
      })
    }

    // MISSING REFRESH TOKEN
    if (params.grant_type === 'refresh_token' && !params.refresh_token) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing refresh token'
      })
    }

    return Promise.resolve(request)
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
   * @returns {Promise<TokenRequest>}
   */
  authenticateClient (request) {
    let method
    const { req } = request

    // Use HTTP Basic Authentication Method
    if (req.headers && req.headers.authorization) {
      method = 'clientSecretBasic'
    }

    // Use HTTP Post Authentication Method
    if (req.body && req.body.client_secret) {
      // Fail if multiple authentication methods are attempted
      if (method) {
        return request.badRequest({
          error: 'unauthorized_client',
          error_description: 'Must use only one authentication method'
        })
      }

      method = 'clientSecretPost'
    }

    // Use Client JWT Authentication Method
    if (req.body && req.body.client_assertion_type) {
      const type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

      // Fail if multiple authentication methods are attempted
      if (method) {
        return request.badRequest({
          error: 'unauthorized_client',
          error_description: 'Must use only one authentication method'
        })
      }

      // Invalid client assertion type
      if (req.body.client_assertion_type !== type) {
        return request.badRequest({
          error: 'unauthorized_client',
          error_description: 'Invalid client assertion type'
        })
      }

      // Missing client assertion
      if (!req.body.client_assertion) {
        return request.badRequest({
          error: 'unauthorized_client',
          error_description: 'Missing client assertion'
        })
      }

      method = 'clientSecretJWT'
    }

    // Missing authentication parameters
    if (!method) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Missing client credentials'
      })
    }

    // Apply the appropriate authentication method
    return request[method](request)
  }

  /**
   * Client Secret Basic Authentication
   *
   * @description
   * HTTP Basic Authentication of client using client_id and client_secret as
   * username and password.
   * @param {TokenRequest} request
   * @returns {Promise<TokenRequest>}
   */
  clientSecretBasic (request) {
    const { req: { headers }, provider } = request
    const authorization = headers.authorization.split(' ')
    const scheme = authorization[0]
    const credentials = new Buffer(authorization[1], 'base64')
      .toString('ascii')
      .split(':')
    const [id, secret] = credentials

   // MALFORMED CREDENTIALS
    if (credentials.length !== 2) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Malformed HTTP Basic credentials'
      })
    }

    // INVALID AUTHORIZATION SCHEME
    if (!/^Basic$/i.test(scheme)) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Invalid authorization scheme'
      })
    }

    // MISSING CREDENTIALS
    if (!id || !secret) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Missing client credentials'
      })
    }

    return provider.backend.get('clients', id).then(client => {

      // UNKNOWN CLIENT
      if (!client) {
        return request.unauthorized({
          error: 'unauthorized_client',
          error_description: 'Unknown client identifier'
        })
      }

      // MISMATCHING SECRET
      if (client.client_secret !== secret) {
        return request.unauthorized({
          error: 'unauthorized_client',
          error_description: 'Mismatching client secret'
        })
      }

      request.client = client
      return request
    })
  }

  /**
   * Client Secret Post
   *
   * @description
   * Authentication of client using client_id and client_secret as HTTP POST
   * body parameters.
   * @param {TokenRequest} request
   * @returns {Promise<TokenRequest>}
   */
  clientSecretPost (request) {
    const { params: { client_id: id, client_secret: secret }, provider } = request

    // MISSING CREDENTIALS
    if (!id || !secret) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Missing client credentials'
      })
    }

    return new Promise((resolve, reject) => {
      provider.backend.get('clients', id).then(client => {

        // UNKNOWN CLIENT
        if (!client) {
          return request.unauthorized({
            error: 'unauthorized_client',
            error_description: 'Unknown client identifier'
          })
        }

        // MISMATCHING SECRET
        if (client.client_secret !== secret) {
          return request.unauthorized({
            error: 'unauthorized_client',
            error_description: 'Mismatching client secret'
          })
        }

        request.client = client

        resolve(request)
      })
    })
  }

  /**
   * Client Secret JWT Authentication
   *
   * TODO RTFS
   * @param request {TokenRequest}
   * @returns {Promise<TokenRequest>}
   */
  clientSecretJWT (request) {
    const { req: { body: { client_assertion: jwt } }, provider} = request
    const payloadB64u = jwt.split('.')[1]
    const payload = JSON.parse(base64url.decode(payloadB64u))

    if (!payload || !payload.sub) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Cannot extract client id from JWT'
      })
    }

    return provider.backend.get('clients', payload.sub)
      .then(client => {
        if (!client) {
          return request.badRequest({
            error: 'unauthorized_client',
            error_description: 'Unknown client'
          })
        }

        if (!client.client_secret) {
          return request.badRequest({
            error: 'unauthorized_client',
            error_description: 'Missing client secret'
          })
        }

        let token = JWT.decode(jwt, client.client_secret)

        if (!token || token instanceof Error) {
          return request.badRequest({
            error: 'unauthorized_client',
            error_description: 'Invalid client JWT'
          })
        }

        // TODO validate the payload

        return request
      })
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
   * @param {TokenRequest} request
   * @returns {Promise<Null>}
   */
  grant (request) {
    const { grantType } = request

    if (grantType === 'authorization_code') {
      return request.authorizationCodeGrant(request)
    }

    if (grantType === 'refresh_token') {
      return request.refreshTokenGrant(request)
    }

    if (grantType === 'client_credentials') {
      return request.clientCredentialsGrant(request)
    }

    // THIS IS SERIOUS TROUBLE
    // REQUEST VALIDATION SHOULD FILTER OUT
    // UNSUPPORTED GRANT TYPES BEFORE WE ARRIVE
    // HERE.
    throw new Error('Unsupported response type')
  }

  /**
   * Authorization Code Grant
   *
   * @param {TokenRequest} request
   * @returns {Promise<Null>}
   */
  authorizationCodeGrant (request) {
    return Promise.resolve({})
      .then(response => request.includeAccessToken(response))
      .then(response => request.includeIDToken(response))
      .then(response => {
        request.res.json(response)
      })
  }

  /**
   * includeAccessToken
   */
  includeAccessToken (response) {
    return AccessToken.issueForRequest(this, response)
  }

  /**
   * includeIDToken
   */
  includeIDToken (response) {
    return IDToken.issueForRequest(this, response)
  }

  /**
   * Refresh Grant
   *
   * @param {TokenRequest} request
   * @returns {Promise<Object>} Resolves to response object
   */
  refreshTokenGrant (request) {
    // TODO: I don't think this.tokenResponse is implemented..
    return AccessToken.refresh(request).then(this.tokenResponse)
  }

  /**
   * OAuth 2.0 Client Credentials Grant
   *
   * @param {TokenRequest} request
   * @returns {Promise<Null>}
   */
  clientCredentialsGrant (request) {
    const { res, client: { default_max_age: expires } } = request

    return AccessToken.issueForRequest(request, res).then(token => {
      let response = {}

      res.set({
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache'
      })

      response.access_token = token
      response.token_type = 'Bearer'
      if (expires) {
        response.expires_in = expires
      }

      res.json(response)
    })
  }
  decodeRequestParam (request) {
    let { params } = request

    if (!params['request']) {
      return Promise.resolve(request)  // Pass through, no request param present
    }

    let requestJwt

    return Promise.resolve()
      .then(() => JWT.decode(params['request']))

      .catch(err => {
        request.redirect({
          error: 'invalid_request_object',
          error_description: err.message
        })
      })

      .then(jwt => { requestJwt = jwt })

      .then(() => {
        if (requestJwt.payload.key) {
          return request.loadCnfKey(requestJwt.payload.key)
            .catch(err => {
              request.redirect({
                error: 'invalid_request_object',
                error_description: 'Error importing cnf key: ' + err.message
              })
            })
        }
      })

      .then(() => request.validateRequestParam(requestJwt))

      .then(requestJwt => {
        request.params = Object.assign({}, params, requestJwt.payload)
      })

      .then(() => request)
  }

  loadCnfKey (jwk) {
    // jwk.use = jwk.use || 'sig'  // make sure key usage is not omitted

    // Importing the key serves as additional validation
    return JWK.importKey(jwk)
      .then(importedJwk => {
        this.cnfKey = importedJwk  // has a cryptoKey property

        return importedJwk
      })
  }

  /**
   * Verify Authorization Code
   * @param request {TokenRequest}
   * @returns {TokenRequest}
   */
  verifyAuthorizationCode (request) {
    const { params, client, provider, grantType } = request

    if (grantType === 'authorization_code') {
      return provider.backend.get('codes', params.code).then(authorizationCode => {

        // UNKNOWN AUTHORIZATION CODE
        if (!authorizationCode) {
          return request.badRequest({
            error: 'invalid_grant',
            error_description: 'Authorization not found'
          })
        }

        // AUTHORIZATION CODE HAS BEEN PREVIOUSLY USED
        if (authorizationCode.used === true) {
          return request.badRequest({
            error: 'invalid_grant',
            error_description: 'Authorization code invalid'
          })
        }

        // AUTHORIZATION CODE IS EXPIRED
        if (authorizationCode.exp < Math.floor(Date.now() / 1000)) {
          return request.badRequest({
            error: 'invalid_grant',
            error_description: 'Authorization code expired'
          })
        }

        // MISMATCHING REDIRECT URI
        if (authorizationCode.redirect_uri !== params.redirect_uri) {
          return request.badRequest({
            error: 'invalid_grant',
            error_description: 'Mismatching redirect uri'
          })
        }

        // MISMATCHING CLIENT ID
        if (authorizationCode.aud !== client.client_id) {
          return request.badRequest({
            error: 'invalid_grant',
            error_description: 'Mismatching client id'
          })
        }

        // TODO mismatching user id?

        request.code = authorizationCode

        // TODO UPDATE AUTHORIZATION CODE TO REFLECT THAT IT'S BEEN USED
        //authorizationCode.use().then(() => Promise.resolve(request))
        return request
      })
    }

    return Promise.resolve(request)
  }

  validateRequestParam (requestJwt) {
    let { params } = this
    let { payload } = requestJwt

    return Promise.resolve()

      .then(() => {
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
      })

      .then(() => {
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
            error_description: 'Mismatching response type in request object',
          })
        }

        // Even if a scope parameter is present in the Request Object value, a scope
        // parameter MUST always be passed using the OAuth 2.0 request syntax
        // containing the openid scope value to indicate to the underlying OAuth 2.0
        // logic that this is an OpenID Connect request.
        if (payload.scope && payload.scope !== params.scope) {
          return this.redirect({
            error: 'invalid_scope',
            error_description: 'Mismatching scope in request object',
          })
        }

        // TODO: What to do with this? SHOULD considered harmful, indeed...
        // If signed, the Request Object SHOULD contain the Claims iss
        // (issuer) and aud (audience) as members. The iss value SHOULD be the
        // Client ID of the RP, unless it was signed by a different party than the
        // RP. The aud value SHOULD be or include the OP's Issuer Identifier URL.
      })

      .then(() => this.validateRequestParamSignature(requestJwt))

      .then(() => requestJwt)
  }

  /**
   * validateRequestParamSignature
   *
   * @param requestJwt {JWT} Decoded request object
   *
   * @returns {Promise}
   */
  validateRequestParamSignature (requestJwt) {
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
      return Promise.resolve()
    }

    let clientJwks = this.client.jwks
    let registeredSigningAlg = this.client['request_object_signing_alg']

    let signedRequest = requestJwt.header.alg !== 'none'
    let signatureRequired = clientJwks ||
      (registeredSigningAlg && registeredSigningAlg !== 'none')

    if (!signedRequest && !signatureRequired) {
      // Unsigned, signature not required - ok
      return Promise.resolve()
    }

    return Promise.resolve()
      .then(() => {
        if (signedRequest && !clientJwks) {
          // No keys pre-registered, but the request is signed. Throw error
          return this.redirect({
            error: 'invalid_request',
            error_description: 'Signed request object, but no jwks pre-registered',
          })
        }

        if (signedRequest && registeredSigningAlg === 'none') {
          return this.redirect({
            error: 'invalid_request',
            error_description: 'Signed request object, but no signature allowed by request_object_signing_alg',
          })
        }

        if (!signedRequest && signatureRequired) {
          return this.redirect({
            error: 'invalid_request',
            error_description: 'Signature required for request object',
          })
        }

        if (registeredSigningAlg && requestJwt.header.alg !== registeredSigningAlg) {
          return this.redirect({
            error: 'invalid_request',
            error_description: 'Request signed by algorithm that does not match registered request_object_signing_alg value',
          })
        }

        // Request is signed. Validate signature against registered jwks
        let keyMatch = requestJwt.resolveKeys(clientJwks)

        if (!keyMatch) {
          return this.redirect({
            error: 'invalid_request',
            error_description: 'Cannot resolve signing key for request object',
          })
        }

        return requestJwt.verify()
          .then(verified => {
            if (!verified) {
              return this.redirect({
                error: 'invalid_request',
                error_description: 'Invalid request object signature',
              })
            }
          })
      })
  }
}


/**
 * Export
 */
module.exports = TokenRequest


