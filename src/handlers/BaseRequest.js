'use strict'

/**
 * Dependencies
 * @ignore
 */
const { URL, URLSearchParams } = require('whatwg-url')
const { JWK } = require('@solid/jose')

const HandledError = require('../errors/HandledError')

/**
 * Request Parameter Mapping
 */
const PARAMS = { GET: 'query', POST: 'body' }

/**
 * Response Mode Mapping
 */
const MODES = { query: '?', fragment: '#' }

/**
 * BaseRequest
 *
 * @class
 * Abstract class for implementing OpenID Connect request handlers.
 */
class BaseRequest {
  /**
   * Request Handler
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   * @param {Provider} provider
   */
  static handle (req, res, provider) {
    throw new Error('Handle must be implemented by BaseRequest subclass')
  }

  /**
   * Constructor
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   * @param {Provider} provider
   */
  constructor (req, res, provider) {
    this.req = req
    this.res = res
    this.provider = provider
    this.defaultRsUri = provider.serverUri
    this.host = provider.host
  }

  /**
   * Get Params
   *
   * @param {BaseRequest} request
   * @returns {Object}
   */
  static getParams (request) {
    const { req } = request
    return req[PARAMS[req.method]] || {}
  }

  /**
   * Get Response Types
   *
   * @param {BaseRequest} request
   * @returns {Array}
   */
  static getResponseTypes (request) {
    const { params: { response_type: type } } = request
    return (typeof type === 'string') ? type.split(' ') : []
  }

  /**
   * Get Response Mode
   *
   * @param {BaseRequest} request
   * @returns {string}
   */
  static getResponseMode (request) {
    let mode
    const { params } = request || {}
    const { response_mode: responseMode, response_type: responseType } = params

    if (responseMode) {
      mode = MODES[responseMode]
    } else if (responseType === 'code' || responseType === 'none') {
      mode = '?'
    } else {
      mode = '#'
    }

    return mode
  }

  /**
   * Response Uri
   *
   * @description
   * Composes and returns a response uri (for an authentication request) for
   * user agent redirection.
   *
   * @param uri {string} Base uri (value of `redirect_uri`)
   *
   * @param data {object} Response parameters hashmap
   *
   * @param responseMode {string} ? or #
   *
   * @returns {string}
   */
  static responseUri (uri, data, responseMode) {
    uri = new URL(uri)
    //
    if (responseMode === '?') {
      return BaseRequest.responseQueryUri(uri, data)
    } else {
      return BaseRequest.responseHashUri(uri, data)
    }
  }

  /**
   * Response Hash Uri
   *
   * @description
   * Composes and returns a hash fragment mode response uri.
   *
   * @param uri {URL} Parsed base uri (value of `redirect_uri`)
   *
   * @param data {object} Response parameters hashmap
   *
   * @returns {string}
   */
  static responseHashUri (uri, data) {
    const responseParams = (new URLSearchParams(data)).toString()

    if (uri.hash) {
      // Base uri already has a hash fragments; append the response params to it
      uri.hash = uri.hash + '&' + responseParams
    } else {
      uri.hash = responseParams
    }

    return uri.toString()
  }

  /**
   * Response Query Uri
   *
   * @description
   * Composes and returns a query mode response uri.
   *
   * @param uri {URL} Parsed base uri (value of `redirect_uri`)
   *
   * @param data {object} Response parameters hashmap
   *
   * @returns {string}
   */
  static responseQueryUri (uri, data) {
    const responseParams = new URLSearchParams(uri.search)

    for (const param in data) {
      responseParams.set(param, data[param])
    }

    uri.search = responseParams

    return uri.toString()
  }

  /**
   * loadCnfKey
   *
   * @description
   * Loads the Proof of Possession confirmation key (from the `request` param)
   *
   * @see https://tools.ietf.org/html/rfc7800#section-3.1
   * @see https://tools.ietf.org/html/draft-ietf-oauth-pop-key-distribution-03#section-5
   *
   * @param jwk {JWK}
   *
   * @returns {Promise<JWK>} Imported key
   */
  async loadCnfKey (jwk) {
    // jwk.use = jwk.use || 'sig'  // make sure key usage is not omitted

    // Importing the key serves as additional validation
    return JWK.importKey(jwk) // has a cryptoKey property
  }

  /**
   * 302 Redirect Response
   */
  redirect (data) {
    const { res, params: { redirect_uri: uri, state }, responseMode } = this

    if (state) {
      data.state = state
    }

    const responseUri = BaseRequest.responseUri(uri, data, responseMode)

    res.redirect(responseUri)

    const error = new HandledError('302 Redirect')

    if (data.error) {
      error.error = data.error
      error.error_description = data.error_description
    }

    throw error
  }

  /**
   * 401 Unauthorized Response
   */
  unauthorized (err) {
    const { res } = this
    const { realm, error, error_description: description } = err

    res.set({
      'WWW-Authenticate':
      `Bearer realm=${realm}, error=${error}, error_description=${description}`
    })

    res.status(401).send('Unauthorized')

    throw new HandledError('401 Unauthorized')
  }

  /**
   * 403 Forbidden Response
   *
   * @param params {Object}
   * @param params.error {string}
   * @param params.error_description {string}
   */
  forbidden (params) {
    const { res } = this

    res.status(403).send('Forbidden')

    const error = new HandledError('403 Forbidden')
    error.error = params.error
    error.error_description = params.error_description
    throw error
  }

  /**
   * 400 Bad Request Response
   *
   * @param params {Object}
   * @param params.error {string}
   * @param params.error_description {string}
   */
  badRequest (params) {
    const { res } = this

    res.set({
      'Cache-Control': 'no-store',
      Pragma: 'no-cache'
    })

    res.status(400).json(params)

    const error = new HandledError('400 Bad Request')

    error.error = params.error || 'invalid_request'
    error.error_description = params.error_description

    throw error
  }

  /**
   * Serves as a general purpose error handler for `.catch()` clauses in
   * Promise chains. Example usage:
   *
   *   ```
   *   return Promise.resolve(request)
   *     .then(request.validate)
   *     .then(request.stepOne)
   *     .then(request.stepTwo)  // etc.
   *     .catch(request.error.bind(request))
   *   ```
   *
   * If at any point (say, in `validate()` or `stepOne()`) the code needs to
   * break out of that promise chain intentionally, it should throw a
   * `HandledError`. For example:
   *
   *   ```
   *   throw new HandledError('400 Bad Request')
   *   ```
   *
   * @param error {HandledError|Error}
   */
  error (error) {
    if (!error.handled) {
      this.internalServerError(error)
    }
  }

  /**
   * Internal Server Error
   */
  internalServerError (err) {
    // TODO: Debug logging here
    const { res } = this
    console.error(err)
    res.status(500).send('Internal Server Error')
  }
}

/**
 * Export
 */
module.exports = BaseRequest
