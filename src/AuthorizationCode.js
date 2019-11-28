/* eslint-disable camelcase */
'use strict'

/**
 * AuthorizationCode
 */
class AuthorizationCode {
  /**
   * @param code {string}
   * @param sub {string}
   * @param aud {string}
   * @param redirect_uri {string}
   * @param exp {number}
   * @param max {number}
   * @param scope {string|Array<string>}
   * @param nonce {string}
   */
  constructor ({ code, sub, aud, redirect_uri, exp, max, scope, nonce } = {}) {
    this.code = code
    this.sub = sub
    this.aud = aud
    this.redirect_uri = redirect_uri
    this.exp = exp
    this.max = max
    this.scope = scope
    this.nonce = nonce
  }
}

/**
 * Export
 */
module.exports = AuthorizationCode
