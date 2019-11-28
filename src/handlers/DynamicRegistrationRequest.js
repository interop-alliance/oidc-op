'use strict'

/**
 * Dependencies
 * @ignore
 */
const { JWT } = require('@solid/jose')
const { random } = require('../crypto')
const BaseRequest = require('./BaseRequest')
const Client = require('../Client')

/**
 * DynamicRegistrationRequest
 */
class DynamicRegistrationRequest extends BaseRequest {
  /**
   * Request Handler
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   * @param {Provider} provider
   */
  static handle (req, res, provider) {
    const request = new DynamicRegistrationRequest(req, res, provider)

    return Promise.resolve(request)
      .then(request.validate)
      .then(request.register)
      .then(request.token)
      .then(request.respond)
      .catch(request.error.bind(request))
  }

  /**
   * Validate
   *
   * @param {DynamicRegistrationRequest} request
   * @returns {DynamicRegistrationRequest}
   */
  validate (request) {
    const registration = request.req.body

    if (!registration) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing registration request body'
      })
    }

    // Return an explicit error on missing redirect_uris
    if (!registration.redirect_uris) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing redirect_uris parameter'
      })
    }

    // generate a client id unless one is provided
    if (!registration.client_id) {
      registration.client_id = request.identifier()
    }

    // generate a client secret for non-implicit clients
    if (!request.implicit(registration)) {
      registration.client_secret = request.secret()
    }

    /**
     * TODO: Validate that the `frontchannel_logout_uri` domain and port is the same as one of the `redirect_uris` values
     * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout
     *
     * The domain, port, and scheme of this URL MUST be the same as that of a
     * registered Redirection URI value.
     */

    // initialize and validate a client
    const client = new Client(registration)
    const validation = client.validate()

    if (!validation.valid) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Client validation error: ' +
          JSON.stringify(validation.error)
      })
    }

    request.client = client
    return request
  }

  /**
   * register
   *
   * @param {DynamicRegistrationRequest} request
   * @returns {Promise}
   */
  register (request) {
    const backend = request.provider.backend
    const client = request.client
    const id = client.client_id

    return backend.put('clients', id, client).then(client => request)
  }

  /**
   * token
   *
   * @param {DynamicRegistrationRequest} request
   * @returns {Promise}
   */
  token (request) {
    const { provider, client } = request
    const { issuer, keys } = provider
    const alg = client.id_token_signed_response_alg

    // create a registration access token
    const jwt = new JWT({
      header: {
        alg
      },
      payload: {
        iss: issuer,
        aud: client.client_id,
        sub: client.client_id
      },
      key: keys.register.signing[alg].privateKey
    })

    // sign the token
    return jwt.encode().then(compact => {
      request.compact = compact
      return request
    })
  }

  /**
   * respond
   *
   * @param {DynamicRegistrationRequest} request
   */
  respond (request) {
    const { client, compact, provider, res } = request

    const clientUri = (new URL('/register/' +
      encodeURIComponent(client.client_id), provider.issuer)).toString()

    const response = Object.assign({}, client, {
      registration_access_token: compact,
      registration_client_uri: clientUri,
      client_id_issued_at: Math.floor(Date.now() / 1000)
    })

    if (client.client_secret) {
      response.client_secret_expires_at = 0
    }

    res.set({
      'Cache-Control': 'no-store',
      Pragma: 'no-cache'
    })

    res.status(201).json(response)
  }

  /**
   * identifier
   *
   * @returns {string}
   */
  identifier () {
    return random(16)
  }

  /**
   * secret
   *
   * @returns {string}
   */
  secret () {
    return random(16)
  }

  /**
   * implicit
   *
   * @param {Object} registration
   * @returns {Boolean}
   */
  implicit (registration) {
    const responseTypes = registration.response_types

    return !!(responseTypes &&
      responseTypes.length === 1 &&
      responseTypes[0] === 'id_token token')
  }
}

/**
 * Export
 */
module.exports = DynamicRegistrationRequest
