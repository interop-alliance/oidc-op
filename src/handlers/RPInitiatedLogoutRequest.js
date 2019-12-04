'use strict'

/**
 * Dependencies
 * @ignore
 */
const qs = require('qs')
const BaseRequest = require('./BaseRequest')
const IDToken = require('../IDToken')
const { JWKSet } = require('@solid/jose')

const DEFAULT_POST_LOGOUT_URI = '/'

/**
 * Session spec defines the following params to the RP Initiated Logout request:
 *   - `id_token_hint`
 *   - `post_logout_redirect_uri`
 *   - `state`
 *
 * @see https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
 * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPInitiated
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#RPInitiated
 */
class RPInitiatedLogoutRequest extends BaseRequest {
  /**
   * @param req {IncomingRequest}
   * @param res {ServerResponse}
   * @param provider {Provider}
   */
  constructor (req, res, provider) {
    super(req, res, provider)
    this.params = RPInitiatedLogoutRequest.getParams(this)
  }

  /**
   * RP Initiated Logout Request Handler
   *
   * @param req {HTTPRequest}
   * @param res {HTTPResponse}
   * @param provider {Provider}
   * @returns {Promise}
   */
  static handle (req, res, provider) {
    const request = new RPInitiatedLogoutRequest(req, res, provider)

    return Promise
      .resolve(request)
      .then(request.validate)
      // From: https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
      // At the logout endpoint, the OP SHOULD ask the End-User whether they want
      // to log out of the OP as well. If the End-User says "yes", then the OP
      // MUST log out the End-User.
      .then(request.clearUserSession.bind(request))
      .then(request.redirectToPostLogoutUri.bind(request))
      .catch(request.error.bind(request))
  }

  /**
   * validateIdTokenHint
   *
   * Validates the `id_token_hint` parameter
   *
   * RECOMMENDED. Previously issued ID Token passed to the logout endpoint as
   * a hint about the End-User's current authenticated session with the Client.
   * This is used as an indication of the identity of the End-User that the RP
   * is requesting be logged out by the OP. The OP *need not* be listed as an
   * audience of the ID Token when it is used as an `id_token_hint` value.
   *
   * @param request {RPInitiatedLogoutRequest}
   *
   * @throws {Error} 400 Bad Request if ID Token hint can't be decoded
   *   or verified
   *
   * @returns {Promise<RPInitiatedLogoutRequest>} Chainable
   */
  async validateIdTokenHint (request) {
    const { provider, params } = request
    const idTokenHint = params.id_token_hint
    let decodedHint

    if (!idTokenHint) {
      return request
    }

    try {
      decodedHint = await IDToken.decode(idTokenHint)
    } catch (error) {
      request.badRequest({ error_description: 'Error decoding ID Token hint' })
    }

    // Importing the provider keys creates a CryptoKey property on each.
    // A CryptoKey object is required for verifying the ID token.
    const jwks = await JWKSet.importKeys(provider.keys.jwks)
    // Resolve which signing key should be used to verify the ID token.
    if (!decodedHint.resolveKeys(jwks)) {
      request.badRequest({
        error_description: 'ID Token hint signing keys cannot be resolved'
      })
    }

    try {
      await decodedHint.verify()
    } catch (cause) {
      console.error('Could not verify ID Token hint:', decodedHint)
      request.badRequest({ error_description: 'Could not verify ID Token hint' })
    }

    request.params.decodedHint = decodedHint

    return request
  }

  /**
   * Validates that `post_logout_redirect_uri` has been registered
   *
   * The value MUST have been previously registered with the OP, either using
   * the `post_logout_redirect_uris` Registration parameter
   * or via another mechanism.
   *
   * @param request {RPInitiatedLogoutRequest}
   *
   * @throws {Error}
   *
   * @returns {Promise<RPInitiatedLogoutRequest>} Chainable
   */
  async validatePostLogoutUri (request) {
    const { provider, params } = request
    const { post_logout_redirect_uri: uri } = params
    const { decodedHint } = params

    if (!uri) {
      return request
    }

    if (!decodedHint) {
      return request.badRequest({
        error_description: 'post_logout_redirect_uri requires id_token_hint'
      })
    }

    // Get the client from the ID Token Hint to validate that the
    // post logout redirect URI has been pre-registered
    const clientId = decodedHint.payload.azp || decodedHint.payload.aud

    const client = await provider.store.clients.get(clientId)
    if (!client) {
      return request.badRequest({
        error_description: 'Invalid ID Token hint (client not found)'
      })
    }

    // Check that the post logout uri has been registered
    if (!client.post_logout_redirect_uris || !client.post_logout_redirect_uris.includes(uri)) {
      return request.badRequest({
        error_description: 'post_logout_redirect_uri must be pre-registered'
      })
    }

    // Valid
    return request
  }

  /**
   * Validate
   *
   * @see https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
   *
   * @param request {RPInitiatedLogoutRequest}
   *
   * @returns {Promise<RPInitiatedLogoutRequest>} Chainable
   */
  validate (request) {
    /**
     * `state` parameter - no validation needed. Will be passed back to the RP
     * in the `redirectToRP()` step.
     */
    return Promise.resolve(request)
      .then(request.validateIdTokenHint)
      .then(request.validatePostLogoutUri)
  }

  /**
   * Redirects the user-agent to a post logout URI. Also passes through the
   * `state` parameter, if supplied by the RP.
   *
   * From the spec:
   * In some cases, the RP will request that the End-User's User Agent to be
   * redirected back to the RP after a logout has been performed. Post-logout
   * redirection is only done when the logout is RP-initiated, in which case the
   * redirection target is the `post_logout_redirect_uri` query parameter value
   * used by the initiating RP; otherwise it is not done.
   *
   * @see https://openid.net/specs/openid-connect-session-1_0.html#RedirectionAfterLogout
   *
   * Implementor's notes:
   * For usability reasons, the user should still be redirected somewhere after
   * logout, even if no redirect uri was passed in by the RP client (we can't
   * just show them a 204/no content). For that reason, we allow the OP host
   * config to provide a default `post_logout_redirect_uri` in case none is
   * provided. Since this is controlled by the host/OP (and not by the RP),
   * this is still respectful of the OAuth2 threat model, and mitigates the
   * risk of rogue redirects.
   */
  redirectToPostLogoutUri () {
    const { host, res, params } = this
    const { state } = params

    let uri = null
    if (params && params.post_logout_redirect_uri) { uri = params.post_logout_redirect_uri }
    if (!uri && host.defaults && host.defaults.post_logout_redirect_uri) { uri = host.defaults.post_logout_redirect_uri }
    if (!uri) { uri = DEFAULT_POST_LOGOUT_URI }

    if (state) {
      const queryString = qs.stringify({ state })
      uri = `${uri}?${queryString}`
    }

    res.redirect(uri) // 302 redirect
  }

  clearUserSession () {
    const session = this.req.session
    session.cookie.expires = new Date(Date.now())
    session.userId = null
    session.subject = null
  }
}

module.exports = RPInitiatedLogoutRequest
