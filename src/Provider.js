/* eslint-disable camelcase */
'use strict'

/**
 * Dependencies
 */
const KeyChain = require('@solid/keychain')
const AuthenticationRequest = require('./handlers/AuthenticationRequest')
const OpenIDConfigurationRequest = require('./handlers/OpenIDConfigurationRequest')
const DynamicRegistrationRequest = require('./handlers/DynamicRegistrationRequest')
const JWKSetRequest = require('./handlers/JWKSetRequest')
const TokenRequest = require('./handlers/TokenRequest')
const UserInfoRequest = require('./handlers/UserInfoRequest')
const RPInitiatedLogoutRequest = require('./handlers/RPInitiatedLogoutRequest')

const DEFAULT_RESPONSE_TYPES_SUPPORTED = [
  'code',
  'code token',
  'code id_token',
  'id_token',
  'id_token token',
  'code id_token token',
  'none'
]
const DEFAULT_RESPONSE_MODES_SUPPORTED = [
  'query',
  'fragment'
]
const DEFAULT_GRANT_TYPES_SUPPORTED = [
  'authorization_code',
  'implicit',
  'refresh_token',
  'client_credentials'
]
const DEFAULT_SUBJECT_TYPES_SUPPORTED = ['public']

/**
 * OpenID Connect Provider
 */
class Provider {
  /**
   * constructor
   *
   * @param [data={}] {object}
   *
   * @param data.store {object} Container for collection persistence
   * @param data.store.clients {FlexDocStore} RP Client registrations
   * @param data.store.codes {FlexDocStore} Authorization codes
   * @param data.store.tokens {FlexDocStore} ID/Access tokens
   * @param data.store.refresh {FlexDocStore} Refresh tokens
   *
   * @param data.issuer {string} Issuer/provider URL
   * @param data.keys {Array<JWK>}
   * @param data.serverUri {string} Used for default Resource Server uri
   */
  constructor (data = {}) {
    const { issuer } = data
    if (!issuer) {
      throw new Error('OpenID Provider must have an issuer.')
    }

    // Non-serializable
    // this.store = data.store
    Object.defineProperty(this, 'store', {
      enumerable: false,
      value: data.store
    })
    Object.defineProperty(this, 'host', {
      enumerable: false, value: data.host
    })

    // Serializable properties
    this.issuer = data.issuer
    this.keys = data.keys
    this.serverUri = data.serverUri
    this.jwks_uri = data.jwks_uri
    this.scopes_supported = data.scopes_supported
    this.response_types_supported = data.response_types_supported ||
      DEFAULT_RESPONSE_TYPES_SUPPORTED
    this.response_modes_supported = data.response_modes_supported ||
      DEFAULT_RESPONSE_MODES_SUPPORTED
    this.grant_types_supported = data.grant_types_supported ||
      DEFAULT_GRANT_TYPES_SUPPORTED
    this.subject_types_supported = data.subject_types_supported ||
      DEFAULT_SUBJECT_TYPES_SUPPORTED
    this.id_token_signing_alg_values_supported =
      data.id_token_signing_alg_values_supported || ['RS256']
    this.id_token_encryption_alg_values_supported =
      data.id_token_encryption_alg_values_supported
    this.id_token_encryption_enc_values_supported =
      data.id_token_encryption_enc_values_supported
    this.userinfo_signing_alg_values_supported =
      data.userinfo_signing_alg_values_supported
    this.userinfo_encryption_alg_values_supported =
      data.userinfo_encryption_alg_values_supported
    this.userinfo_encryption_enc_values_supported =
      data.userinfo_encryption_enc_values_supported
    this.request_object_signing_alg_values_supported =
      data.request_object_signing_alg_values_supported
    this.request_object_encryption_alg_values_supported =
      data.request_object_encryption_alg_values_supported
    this.request_object_encryption_enc_values_supported =
      data.request_object_encryption_enc_values_supported
    this.token_endpoint_auth_methods_supported =
      data.token_endpoint_auth_methods_supported || 'client_secret_basic'
    this.token_endpoint_auth_signing_alg_values_supported =
      data.token_endpoint_auth_signing_alg_values_supported || ['RS256']
    this.display_values_supported = data.display_values_supported || []
    this.claim_types_supported = data.claim_types_supported || ['normal']
    this.claims_supported = data.claims_supported || []
    this.service_documentation = data.service_documentation
    this.claims_locales_supported = data.claims_locales_supported
    this.ui_locales_supported = data.ui_locales_supported
    this.claims_parameter_supported = data.claims_parameter_supported || false
    this.request_parameter_supported = data.request_parameter_supported
    if (this.request_parameter_supported === undefined) {
      this.request_parameter_supported = true
    }
    this.request_uri_parameter_supported = data.request_uri_parameter_supported || false
    this.require_request_uri_registration = data.require_request_uri_registration || false
    this.op_policy_uri = data.op_policy_uri
    this.op_tos_uri = data.op_tos_uri
    this.check_session_iframe = data.check_session_iframe
    this.end_session_endpoint = data.end_session_endpoint

    this.authorization_endpoint = data.authorization_endpoint ||
      (new URL('/authorize', issuer)).toString()
    this.token_endpoint = data.token_endpoint ||
      (new URL('/token', issuer)).toString()
    this.userinfo_endpoint = data.userinfo_endpoint ||
      (new URL('/userinfo', issuer)).toString()
    this.jwks_uri = data.jwks_uri || (new URL('/jwks', issuer)).toString()
    this.registration_endpoint = data.registration_endpoint ||
      (new URL('/register', issuer)).toString()
    this.check_session_iframe = data.check_session_iframe ||
      (new URL('/session', issuer)).toString()
    this.end_session_endpoint = data.end_session_endpoint ||
      (new URL('/logout', issuer)).toString()
  }

  /**
   * from
   *
   * @description
   * Factory method, resolves with a Provider instance, initialized from the
   * provided serialized provider `data`.
   * If data includes an exported JWK Set, the provider's keychain is imported,
   * otherwise, a new keychain is generated.
   *
   * @param data {Object} Parsed JSON of a serialized Provider
   *
   * @returns {Promise<Provider>}
   */
  static async from (data) {
    const provider = new Provider(data)

    await provider.initializeKeyChain(provider.keys)

    return provider
  }

  /**
   * initializeKeyChain
   *
   * @param data {Object} Parsed JSON of a serialized provider's .keys property
   * @returns {Promise<Provider>} Resolves to self, chainable
   */
  initializeKeyChain (data) {
    if (!data) {
      return this.generateKeyChain()
    }

    return this.importKeyChain(data)
  }

  /**
   * generateKeyChain
   */
  generateKeyChain () {
    const modulusLength = 2048

    const descriptor = {
      id_token: {
        signing: {
          RS256: { alg: 'RS256', modulusLength },
          RS384: { alg: 'RS384', modulusLength },
          RS512: { alg: 'RS512', modulusLength }
        },
        encryption: {
          // ?
        }
      },
      token: {
        signing: {
          RS256: { alg: 'RS256', modulusLength },
          RS384: { alg: 'RS384', modulusLength },
          RS512: { alg: 'RS512', modulusLength }
        },
        encryption: {}
      },
      userinfo: {
        encryption: {}
      },
      register: {
        signing: {
          RS256: { alg: 'RS256', modulusLength }
        }
      }
    }

    this.keys = new KeyChain(descriptor)
    return this.keys.rotate()
  }

  /**
   * importKeyChain
   *
   * @param data {Object} Parsed JSON of a serialized provider's .keys property
   * @returns {Promise<Provider>} Resolves to self, chainable
   */
  async importKeyChain (data) {
    if (!data) {
      throw new Error('Cannot import empty keychain')
    }

    this.keys = await KeyChain.restore(data)
    return this
  }

  /**
   * openidConfiguration
   */
  get openidConfiguration () {
    return JSON.stringify(this)
  }

  /**
   * jwkSet
   */
  get jwkSet () {
    return this.keys.jwkSet
  }

  /**
   * Authorize
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  authorize (req, res) {
    AuthenticationRequest.handle(req, res, this)
  }

  /**
   * Logout
   *
   * Bound to the OP's `end_session_endpoint` uri
   *
   * @param req {HTTPRequest}
   * @param res {HTTPResponse}
   */
  logout (req, res) {
    RPInitiatedLogoutRequest.handle(req, res, this)
  }

  /**
   * Discover
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  discover (req, res) {
    OpenIDConfigurationRequest.handle(req, res, this)
  }

  /**
   * JWKs
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  jwks (req, res) {
    JWKSetRequest.handle(req, res, this)
  }

  /**
   * Register
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  register (req, res) {
    DynamicRegistrationRequest.handle(req, res, this)
  }

  /**
   * Token
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  token (req, res) {
    TokenRequest.handle(req, res, this)
  }

  /**
   * UserInfo
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  userinfo (req, res) {
    UserInfoRequest.handle(req, res, this)
  }
}

/**
 * Export
 */
module.exports = Provider
