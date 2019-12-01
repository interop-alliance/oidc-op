/* eslint-disable camelcase */
'use strict'

const DEFAULT_RESPONSE_TYPES = ['code']
const DEFAULT_GRANT_TYPES = ['authorization_code']

/**
 * Client
 */
class Client {
  /**
   * @param redirect_uris {Array<string>} Required.
   * @param client_id
   * @param client_secret
   * @param response_types
   * @param grant_types
   * @param application_type
   * @param contacts
   * @param client_name
   * @param logo_uri
   * @param client_uri
   * @param policy_uri
   * @param tos_uri
   * @param jwks_uri
   * @param jwks
   * @param subject_type
   * @param sector_identifier_uri
   * @param id_token_signed_response_alg
   * @param id_token_encrypted_response_alg
   * @param id_token_encrypted_response_alg
   * @param id_token_encrypted_response_enc
   * @param userinfo_signed_response_alg
   * @param userinfo_encrypted_response_alg
   * @param userinfo_encrypted_response_enc
   * @param request_object_signing_alg
   * @param request_object_encryption_alg
   * @param request_object_encryption_enc
   * @param token_endpoint_auth_method
   * @param token_endpoint_auth_signing_alg
   * @param default_max_age
   * @param require_auth_time
   * @param default_acr_values
   * @param initiate_login_uri
   * @param request_uris
   * @param post_logout_redirect_uris
   * @param frontchannel_logout_uri
   * @param frontchannel_logout_session_required
   */
  constructor ({
    redirect_uris, client_id, client_secret,
    response_types = DEFAULT_RESPONSE_TYPES,
    grant_types = DEFAULT_GRANT_TYPES,
    application_type = 'web', contacts, client_name, logo_uri,
    client_uri, policy_uri, tos_uri, jwks_uri, jwks, subject_type,
    sector_identifier_uri, id_token_signed_response_alg = 'RS256',
    id_token_encrypted_response_alg,
    id_token_encrypted_response_enc, userinfo_signed_response_alg,
    userinfo_encrypted_response_alg, userinfo_encrypted_response_enc,
    request_object_signing_alg, request_object_encryption_alg,
    request_object_encryption_enc,
    token_endpoint_auth_method = 'client_secret_basic',
    token_endpoint_auth_signing_alg, default_max_age,
    require_auth_time, default_acr_values, initiate_login_uri,
    request_uris, post_logout_redirect_uris, frontchannel_logout_uri,
    frontchannel_logout_session_required
  }) {
    this.redirect_uris = redirect_uris
    this.client_id = client_id
    this.client_secret = client_secret
    this.response_types = response_types
    this.grant_types = grant_types
    this.application_type = application_type
    this.contacts = contacts
    this.client_name = client_name
    this.logo_uri = logo_uri
    this.client_uri = client_uri
    this.policy_uri = policy_uri
    this.tos_uri = tos_uri
    this.jwks_uri = jwks_uri
    this.jwks = jwks
    this.sector_identifier_uri = sector_identifier_uri
    this.subject_type = subject_type
    this.id_token_signed_response_alg = id_token_signed_response_alg
    this.id_token_encrypted_response_alg = id_token_encrypted_response_alg
    this.id_token_encrypted_response_alg = id_token_encrypted_response_alg
    this.id_token_encrypted_response_enc = id_token_encrypted_response_enc
    this.userinfo_signed_response_alg = userinfo_signed_response_alg
    this.userinfo_encrypted_response_alg = userinfo_encrypted_response_alg
    this.userinfo_encrypted_response_enc = userinfo_encrypted_response_enc
    this.request_object_signing_alg = request_object_signing_alg
    this.request_object_encryption_alg = request_object_encryption_alg
    this.request_object_encryption_enc = request_object_encryption_enc
    this.token_endpoint_auth_method = token_endpoint_auth_method
    this.token_endpoint_auth_signing_alg = token_endpoint_auth_signing_alg
    this.default_max_age = default_max_age
    this.require_auth_time = require_auth_time
    this.default_acr_values = default_acr_values
    this.initiate_login_uri = initiate_login_uri
    this.request_uris = request_uris
    this.post_logout_redirect_uris = post_logout_redirect_uris
    this.frontchannel_logout_uri = frontchannel_logout_uri
    this.frontchannel_logout_session_required = frontchannel_logout_session_required
  }

  validate () {
    if (!this.redirect_uris) {
      return {
        valid: false,
        error: new Error('Client.redirect_uris is required.')
      }
    }
    return { valid: true }
  }
}

/**
 * Export
 */
module.exports = Client
