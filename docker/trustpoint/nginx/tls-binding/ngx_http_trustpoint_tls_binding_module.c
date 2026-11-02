/*
 * Copyright (c) 2026 The Trustpoint Project Authors
 * SPDX-License-Identifier: MIT
 *
 * RFC 5929 tls-unique for the downstream TLS connection. This intentionally
 * does not treat TLS 1.3 Finished messages as tls-unique: that binding type is
 * undefined for TLS 1.3. RFC 9266 exporters need a separately agreed profile.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_trustpoint_tls_binding_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_trustpoint_tls_binding_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t supported);

static ngx_http_module_t ngx_http_trustpoint_tls_binding_module_ctx = {
    ngx_http_trustpoint_tls_binding_add_variables,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_trustpoint_tls_binding_module = {
    NGX_MODULE_V1,
    &ngx_http_trustpoint_tls_binding_module_ctx,
    NULL,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_trustpoint_tls_binding_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *variable;
    ngx_str_t unique = ngx_string("trustpoint_tls_unique");
    ngx_str_t supported = ngx_string("trustpoint_tls_unique_supported");

    variable = ngx_http_add_variable(cf, &unique, NGX_HTTP_VAR_NOCACHEABLE);
    if (variable == NULL) {
        return NGX_ERROR;
    }
    variable->get_handler = ngx_http_trustpoint_tls_binding_variable;
    variable->data = 0;

    variable = ngx_http_add_variable(cf, &supported, NGX_HTTP_VAR_NOCACHEABLE);
    if (variable == NULL) {
        return NGX_ERROR;
    }
    variable->get_handler = ngx_http_trustpoint_tls_binding_variable;
    variable->data = 1;
    return NGX_OK;
}

static ngx_int_t
ngx_http_trustpoint_tls_binding_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t supported)
{
    SSL         *ssl;
    size_t       length;
    u_char       finished[EVP_MAX_MD_SIZE];
    ngx_str_t    source, encoded;

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = supported ? 1 : 0;
    v->data = (u_char *) (supported ? "0" : "");

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }
    ssl = r->connection->ssl->connection;
    /* EMS prevents triple-handshake attacks. Refuse renegotiated connections
     * rather than accidentally returning a subsequent handshake's Finished. */
    if (SSL_version(ssl) != TLS1_2_VERSION
        || SSL_is_init_finished(ssl) != 1
        || SSL_get_extms_support(ssl) != 1
        || SSL_total_renegotiations(ssl) != 0)
    {
        return NGX_OK;
    }

    /* The client sends Finished first on a full handshake; the server sends
     * it first on a resumed handshake (RFC 5929 section 3.1). */
    if (SSL_session_reused(ssl)) {
        length = SSL_get_finished(ssl, finished, sizeof(finished));
    } else {
        length = SSL_get_peer_finished(ssl, finished, sizeof(finished));
    }
    if (length == 0 || length > sizeof(finished)) {
        return NGX_OK;
    }

    if (supported) {
        v->data = (u_char *) "1";
        return NGX_OK;
    }
    source.data = finished;
    source.len = length;
    encoded.len = ngx_base64_encoded_length(length);
    encoded.data = ngx_pnalloc(r->pool, encoded.len);
    if (encoded.data == NULL) {
        return NGX_ERROR;
    }
    ngx_encode_base64(&encoded, &source);
    v->data = encoded.data;
    v->len = encoded.len;
    return NGX_OK;
}
