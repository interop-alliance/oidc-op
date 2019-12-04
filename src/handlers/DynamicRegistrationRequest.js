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
  static async handle (req, res, provider) {
    let request
    try {
      request = new DynamicRegistrationRequest(req, res, provider)
      const registration = request.initRegistration()
      request.client = request.initClient(registration)
      await request.register()
      request.compact = await request.token()
      request.respond()
    } catch (error) {
      request.error(error)
    }
  }

  /**
   * initRegistration
   *
   * @returns {object} Initialized client registration
   */
  initRegistration () {
    const registration = this.req.body
    if (!registration) {
      return this.badRequest({
        error: 'invalid_request',
        error_description: 'Missing registration request body'
      })
    }

    // Return an explicit error on missing redirect_uris
    if (!registration.redirect_uris) {
      return this.badRequest({
        error: 'invalid_request',
        error_description: 'Missing redirect_uris parameter'
      })
    }

    // generate a client id unless one is provided
    if (!registration.client_id) {
      registration.client_id = this.identifier()
    }

    // generate a client secret for non-implicit clients
    if (!this.implicit(registration)) {
      registration.client_secret = this.secret()
    }

    /**
     * TODO: Validate that the `frontchannel_logout_uri` domain and port is the same as one of the `redirect_uris` values
     * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout
     *
     * The domain, port, and scheme of this URL MUST be the same as that of a
     * registered Redirection URI value.
     */
    return registration
  }

  initClient (registration) {
    // initialize and validate a client
    const client = new Client(registration)
    const validation = client.validate()

    if (!validation.valid) {
      return this.badRequest({
        error: 'invalid_request',
        error_description: 'Client validation error: ' +
          JSON.stringify(validation.error)
      })
    }
    return client
  }

  /**
   * register
   *
   * @returns {Promise}
   */
  async register () {
    const { client, provider } = this
    const id = client.client_id

    return provider.store.clients.put(id, client)
  }

  /**
   * token
   *
   * @param {DynamicRegistrationRequest} request
   * @returns {Promise<string>} Encoded compact jwt
   */
  async token () {
    const { provider, client } = this
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
    return jwt.encode()
  }

  /**
   * respond
   */
  respond () {
    const { client, compact, provider, res } = this

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
