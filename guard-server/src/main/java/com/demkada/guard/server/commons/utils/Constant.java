package com.demkada.guard.server.commons.utils;

/*
 * Copyright 2019 DEMKADA.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author <a href="mailto:kad@demkada.com">Kad D.</a>
*/


public final class Constant {

    public static final String GUARD = "guard";

    public static final String DEFAULT_CASSANDRA_CLUSTER = "127.0.0.1";
    public static final String DEFAULT_CASSANDRA_DATACENTER = "datacenter1";
    public static final String DRIVER_CASSANDRA_CLUSTER_NAME = "guard-cassandra";
    public static final String CASSANDRA_CLUSTER_CONFIG_KEY = "guard.cassandra.cluster.addresses";
    public static final String CASSANDRA_CLUSTER_PORT_KEY = "guard.cassandra.cluster.port";
    public static final int    DEFAULT_CASSANDRA_PORT = 9042;
    public static final String CASSANDRA_DATACENTER_CONFIG_KEY = "guard.cassandra.dc.local";
    public static final String CASSANDRA_CLUSTER_SSL_CONFIG_KEY = "guard.cassandra.cluster.ssl";

    public static final String SG_SIGNIN = "sg-signin";
    public static final String CDN_CONNECT = "cdn-connect";
    public static final String SAFE = "safe";
    public static final String SG_CONNECT = "sg-connect";

    public static final String CONTENT_TYPE_JSON = "application/json";
    public static final String UTC = "UTC";

    public static final String EMAIL = "email";
    public static final String EMAIL_VERIFIED = "email_verified";
    public static final String PASS = "pwd";
    public static final String GIVEN_NAME = "given_name";
    public static final String FAMILY_NAME = "family_name";
    public static final String ADDRESS = "address";
    public static final String PHONE_NUMBER = "phone_number";
    public static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    public static final String SUB = "sub";
    public static final String ID_ORIGIN = "guard_id_origin";
    public static final String DISABLE = "disable";
    public static final String SECURITY_QUESTION = "security_question";

    public static final String GUARD_HTTPS_P12PASS_CONFIG_KEY = "guard.https.p12.password";
    public static final String GUARD_HTTPS_P12PATH_CONFIG_KEY = "guard.https.p12.path";
    public static final String GUARD_HTTPS_PORT_CONFIG_KEY = "guard.https.port";
    public static final String SARKY_CLUSTER_WIDE_MAP = "guard-cluster-wide-map";
    public static final String GUARD_KEYPAIR = "guard-keypair";
    public static final String KEYPAIR_LOCK = "keypair-lock";
    public static final String GUARD_JWT_ISSUER = "guard.jwt.issuer";
    public static final String GUARD_COOKIE_NAME = "guard.cookie.name";
    public static final String GUARD_COOKIE_DOMAIN = "guard.cookie.domain" ;
    public static final String HTTP_STATUS_CODE = "status_code";
    public static final String ERROR_MESSAGE = "error_message";
    public static final String ERROR_CODE = "error_code";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String SMTP_SERVER_HOST = "guard.smtp.server.host";
    public static final String SMTP_SERVER_PORT = "guard.smtp.server.port";
    public static final String SMTP_FROM = "guard.smtp.from";
    public static final String DO_NOT_REPLY_EMAIL = "guard-donotreply@demkada.com";
    public static final String CONTACT_EMAIL = "contact@demkada.com";
    public static final String GUARD_SERVER_HOST = "guard.server.host";
    public static final String GUARD_CONTACT = "guard.contact";
    public static final String MAIL_MANAGER_QUEUE = "guard.mail.manager.queue";
    public static final String TYPE = "type";
    public static final String ACTION = "action";
    public static final String USER = "user";
    public static final String RESPONSE = "response";
    public static final String PAYLOAD = "payload";
    public static final String CRYPTO_MANAGER_QUEUE = "guard.crypto.manager.queue";
    public static final String ACTION_GENERATE_USER_TOKEN = "generate-user-token";
    public static final String ACTION_VALIDATE_ENCRYPTED_TOKEN = "validate-encrypted-user-token";
    public static final String EXP = "exp";
    public static final String ACTION_GENERATE_ENCRYPTED_USER_TOKEN = "generate-encrypted-user-token";
    public static final String ACTION_EMAIL_CONFIRMATION_REQUEST = "email-confirmation-request";
    public static final String ACTION_EMAIL_PASS_RESET_REQUEST_OK = "email-password-reset-request-ok";
    public static final String ACTION_EMAIL_PASS_RESET_REQUEST_KO = "email-password-reset-request-ko";
    public static final String ACTION_EMAIL_PASS_RESET_RESULT = "email-password-reset-result";
    public static final String ACTION_EMAIL_CONFIRMATION_RESULT = "email-confirmation-result";
    public static final String ACTION_VALIDATE_TOKEN = "validate-token";
    public static final String ACTION_ENCRYPT_STRING = "encrypt-string";
    public static final String ACTION_DECRYPT_STRING = "decrypt-string";
    public static final String EMAIL_INPUT = "email-input";
    public static final String ACTION_INSERT_USER = "insert-user";
    public static final String ACTION_GET_USER_BY_EMAIL = "get-user-by-email";
    public static final String USER_MANAGER_QUEUE = "guard.user.manager.queue";
    public static final String ACTION_GET_USERS = "get-users";
    public static final String ACTION_UPDATE_USER = "update-user";
    public static final String ACTION_CHANGE_USER_STATUS = "change-user-status";
    public static final String STATUS = "status";
    public static final String ACTION_CHANGE_EMAIL_STATUS = "change-email-status";
    public static final String ACTION_CHANGE_PHONE_STATUS = "change-phone-status";
    public static final String ACTION_CHANGE_PASS = "change-password";
    public static final String PIN = "pin";
    public static final String PERMISSIONS = "guard_permissions";
    public static final String ATTRIBUTES = "guard_attributes";
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_NAME = "client_name";
    public static final String CLIENTS_BY_ID = "clients_by_id";
    public static final String USERS_BY_EMAIL = "users_by_email";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String CLIENT_DESCRIPTION = "client_description";
    public static final String CLIENT_REDIRECT_URIS = "client_redirect_uris";
    public static final String CERT = "cert";
    public static final String CLIENT_MANAGERS = "client_managers";
    public static final String CLIENT_LABELS = "client_labels";
    public static final String CLIENT_ACCESS_POLICIES = "client_access_policies";
    public static final String CLIENT_MANAGER_QUEUE = "guard.client.manager.queue";
    public static final String ACTION_INSERT_CLIENT = "insert-client";
    public static final String ACTION_GET_CLIENTS = "get-clients";
    public static final String ACTION_GET_CLIENT_BY_ID = "get-client-by-id";
    public static final String ACTION_UPDATE_CLIENT = "update-client";
    public static final String ACTION_CHANGE_CLIENT_STATUS = "change-client-status";
    public static final String ACTION_CHANGE_SECRET = "change-secret";
    public static final String CLIENT = "client";
    public static final String GUARD_SERVER_ADMIN = "guard.server.admin";
    public static final String ACTION_NOT_ALLOWED = "action not allowed";
    public static final String NO_VALID_EMAIL_ADDRESS = "Not a valid email address";
    public static final String SCOPES_BY_NAME = "scopes_by_name";
    public static final String NAME = "name";
    public static final String EN_DESCRIPTION = "en_description";
    public static final String FR_DESCRIPTION = "fr_description";
    public static final String RESTRICTED = "restricted";
    public static final String MACHINE_MFA = "machine_mfa";
    public static final String END_USER_MFA = "end_user_mfa";
    public static final String CLIENT_ID_LIST = "client_id_list";
    public static final String SCOPE_MANAGERS = "scope_managers";
    public static final String REFRESH_TOKEN_TTL = "refresh_token_ttl";
    public static final String CONSENT_TTL = "consent_ttl";
    public static final String ACTION_INSERT_SCOPE = "insert-scope";
    public static final String ACTION_GET_SCOPES = "get-scopes";
    public static final String ACTION_GET_SCOPE_BY_NAME = "get-scope-by-name";
    public static final String ACTION_UPDATE_SCOPE = "update-scope";
    public static final String ACTION_DELETE_SCOPE = "delete-scope";
    public static final String SCOPE = "scope";
    public static final String ALL = "all";
    public static final String SCOPE_MANAGER_QUEUE = "guard.scope.manager.queue";
    public static final String CONSENTS_BY_SCOPE = "consents_by_scope";
    public static final String SCOPE_NAME = "scope_name";
    public static final String USER_EMAIL = "user_email";
    public static final String TIMESTAMP = "timestamp";
    public static final String CONSENTS_BY_USER = "consents_by_user";
    public static final String ACTION_DELETE_CONSENT = "delete-consent";
    public static final String CONSENT_MANAGER_QUEUE = "guard.consent.manager.queue";
    public static final String ACTION_INSERT_CONSENT = "insert-consent";
    public static final String ACTION_GET_CONSENTS = "get-consents";
    public static final String CONSENT = "consent";
    public static final String GUARD_CRYPTO_KEYSTORE_CONFIG_KEY = "guard.crypto.keystore.path";
    public static final String GUARD_CRYPTO_KEYSTORE_PASS_CONFIG_KEY = "guard.crypto.keystore.password";
    public static final String GUARD_CRYPTO_RSA_KEYPAIR_ALIAS = "guard.crypto.rsa.keypair.alias";
    public static final String GUARD_CRYPTO_AES_KEY_FOR_PK_ALIAS = "guard.crypto.aes.key.pk.alias";
    public static final String GUARD_CRYPTO_AES_KEY_FOR_DATA_ALIAS = "guard.crypto.aes.key.data.alias";
    public static final String ACTION_ENCRYPT_USER_MODEL_PII = "encrypt-user-pii";
    public static final String ACTION_DECRYPT_USER_MODEL_PII = "decrypt-user-pii";
    public static final String ACTION_DECRYPT_PRIMARY_KEY = "decrypt-primary-key";
    public static final String ACTION_ENCRYPT_PRIMARY_KEY = "encrypt-primary-key";
    public static final String ACTION_ENCRYPT_STRING_SET = "encrypt-string-set";
    public static final String ACTION_DECRYPT_STRING_SET = "decrypt-string-set";
    public static final String GUARD_KMIP_SERVER = "guard.kmip.server";
    public static final String GUARD_KMIP_SERVER_HOST = "guard.kmip.server.url";
    public static final String GUARD_KMIP_SERVER_PORT = "guard.kmip.server.port";
    public static final String GUARD_KMIP_SERVER_USER_LOGIN = "guard.kmip.server.user.login";
    public static final String GUARD_KMIP_SERVER_USER_PASS = "guard.kmip.server.user.password";
    public static final String GUARD_KMIP_SERVER_KEYSTORE_PASS = "guard.kmip.server.keystore.pass";
    public static final String GUARD_KMIP_SERVER_KEYSTORE_PATH = "guard.kmip.server.keystore.path";
    public static final String GUARD_KMIP_SERVER_KEYSTORE_CERT_ALIAS = "guard.kmip.server.keystore.cert.alias";
    public static final String GUARD_KMIP_SERVER_AES_PK_CIPHER_KEY = "guard.kmip.server.aes.pk.cipher.key";
    public static final String GUARD_KMIP_SERVER_AES_DATA_CIPHER_KEY = "guard.kmip.server.aes.data.cipher.key";
    public static final String GUARD_KMIP_SERVER_RSA_PRIVATE_KEY = "guard.kmip.server.rsa.privateKey";
    public static final String ACTION_GET_RSA_PUBLIC_KEY = "get-rsa-public-key";
    public static final String OAUTH2_MANAGER_QUEUE = "guard.oauth2.manager.queue";
    public static final String CLIENT_TYPE = "client_type";
    public static final String LOCATION = "Location";
    public static final String ERROR = "error";
    public static final String CONTENT_X_FORM_URLENCODED = "application/x-www-form-urlencoded";
    public static final String ORIGINAL_URL = "original_url";
    public static final String AUTHZ_CODE = "authz_code";
    public static final String CODE = "code";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String PRINCIPAL = "principal";
    public static final String GRANT_TYPE = "grant_type";
    public static final String STATE = "state";
    public static final String EXPIRE_AT = "expire_at";
    public static final long DEFAULT_CONSENT_TTL = 360L;
    public static final long DEFAULT_REFRESH_TOKEN_TTL= 720L;
    public static final String ACTION_GENERATE_OAUTH2_TOKEN = "generate-oauth2-token";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String ID = "id";
    public static final String ISSUE_AT = "issue_at";
    public static final String TRUST_CA_CHAIN = "trust_ca_chain";
    public static final String GUARD_CLIENT_CERT_HEADER = "guard.client.cert.header";
    public static final String X509_HASH = "x509_hash";
    public static final String IAT = "iat";
    public static final String AUTH_TIME = "auth_time";
    public static final String GUARD_SUB_TYPE = "guard_sub_type";
    public static final String AUTH_METHOTH = "amr";
    public static final String USER_TOKEN = "user_token";
    public static final String AUDIENCE = "aud";
    public static final String GUARD_OAUTH2_OPAQUE_ACCESS_TOKEN = "guard.oauth2.opaque-access-token";
    public static final String GUARD_SERVER_ENABLE_CORS_ON_OAUHT2_TOKEN_ENDPOINT = "guard.server.enable-cors-on-oauth2-token-endpoint";
    public static final String GUARD_CRYPTO_INSTANCES = "guard.crypto.instances";
    public static final String GUARD_USERS_INSTANCES = "guard.users.instances";
    public static final String GUARD_CLIENTS_INSTANCES = "guard.clients.instances";
    public static final String GUARD_SCOPE_INSTANCES = "guard.scope.instances";
    public static final String GUARD_CONSENT_INSTANCES = "guard.consent.instances";
    public static final String GUARD_HTTP_INSTANCES = "guard.http.instances";
    public static final String GUARD_ADAPTER_INSTANCES = "guard.adapter.instances";
    public static final String GUARD_EB_P12PASS_CONFIG_KEY = "guard.eb.p12.password";
    public static final String GUARD_EB_P12PATH_CONFIG_KEY = "guard.eb.p12.path";
    public static final String ACR = "acr";
    public static final String TOKEN_TYPE = "token_type";
    public static final String BEARER = "Bearer";
    public static final String EXPIRE_IN = "expires_in";
    public static final String ID_TOKEN = "id_token";
    public static final String NONCE = "nonce";
    public static final String OPENID = "openid";
    public static final String CACHE_CONTROL = "Cache-Control";
    public static final String NO_STORE = "no-store";
    public static final String NO_CACHE = "no-cache";
    public static final String PRAGMA = "Pragma";
    public static final String CONTENT_TYPE = "Content-Type";

    public static final String OAUTH2_ERROR_CODE_INVALID_REQUEST = "invalid_request";
    public static final String OAUTH2_ERROR_CODE_ACCESS_DENIED = "access_denied";
    public static final String OAUTH2_ERROR_CODE_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String OAUTH2_ERROR_CODE_INVALID_SCOPE = "invalid_scope";
    public static final String OAUTH2_ERROR_CODE_SERVER_ERROR = "server_error";
    public static final String OAUTH2_ERROR_CODE_UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String OAUTH2_ERROR_CODE_TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
    public static final String ACTION_VALIDATE_OAUTH2_TOKEN = "validate-oauth2-token";
    public static final String ACTIVE = "active";
    public static final String USERNAME = "username";

    public static final String LOCALE_FR = "fr";
    public static final String LOCALE_EN = "en";

    public static final String TEMPLATE_PATH_PREFIX = "classpath:/template/email/";
    public static final String GUARD_EMAIL_TEMPLATE_DIRECTORY = "guard.email.template.directory";

    public static final String GUARD_CONFIRM_ACCOUNT_EMAIL_TITLE_EN = "guard.email.confirmation.title.en";
    public static final String DEFAULT_CONFIRM_ACCOUNT_EMAIL_TITLE_EN = "Confirm your Guard account";

    public static final String GUARD_CONFIRM_ACCOUNT_EMAIL_TITLE_FR = "guard.email.confirmation.title.fr";
    public static final String DEFAULT_CONFIRM_ACCOUNT_EMAIL_TITLE_FR = "Confirmez votre compte Guard";

    public static final String GUARD_VERIFIED_ACCOUNT_EMAIL_TITLE_EN = "guard.email.account.verified.title.en";
    public static final String DEFAULT_VERIFIED_ACCOUNT_EMAIL_TITLE_EN = "Your Guard account has been verified";

    public static final String GUARD_VERIFIED_ACCOUNT_EMAIL_TITLE_FR = "guard.email.account.verified.title.fr";
    public static final String DEFAULT_VERIFIED_ACCOUNT_EMAIL_TITLE_FR = "Votre compte Guard a bien été vérifié";

    public static final String GUARD_RESET_PASS_REQUEST_EMAIL_TITLE_EN = "guard.email.reset.password.request.title.en";
    public static final String DEFAULT_RESET_PASS_REQUEST_EMAIL_TITLE_EN = "Your Guard account password reset request";

    public static final String GUARD_RESET_PASS_REQUEST_EMAIL_TITLE_FR = "guard.email.reset.password.request.title.fr";
    public static final String DEFAULT_RESET_PASS_REQUEST_EMAIL_TITLE_FR = "Demande de réinitialisation de votre mot de passe Guard";

    public static final String GUARD_CHANGE_PASS_SUCCESS_EMAIL_TITLE_EN = "guard.email.change.password.success.title.en";
    public static final String DEFAULT_CHANGE_PASS_SUCCESS_EMAIL_TITLE_EN = "You have successfully change your Guard's account password";


    public static final String GUARD_CHANGE_PASS_SUCCESS_EMAIL_TITLE_FR = "guard.email.change.password.success.title.fr";
    public static final String DEFAULT_CHANGE_PASS_SUCCESS_EMAIL_TITLE_FR = "Réinitilisation de votre mot de passe Guard réussie";

    public static final String ADAPTERS_BY_ID = "adapters_by_id";
    public static final String DESCRIPTION = "description";
    public static final String LOGO_URL = "logo_url";
    public static final String TRIGGER_ON_HOSTNAME = "trigger_on_hostname";
    public static final String ADAPTER_URL = "adapter_url";
    public static final String PUBLIC_KEY = "public_key";
    public static final String ADAPTER_MANAGER_QUEUE = "guard.adapter.manager.queue";
    public static final String ACTION_INSERT_ADAPTER = "insert-adapter";
    public static final String ACTION_GET_ADAPTERS = "get-adapters";
    public static final String ACTION_GET_ADAPTER_BY_ID = "get-adapter-by-id";
    public static final String ACTION_UPDATE_ADAPTER = "update-adapter";
    public static final String ACTION_DELETE_ADAPTER = "delete-adapter";
    public static final String ADAPTER = "adapter";
    public static final String GUARD_ADAPTER_NONCE = "guard_adapter_nonce";
    public static final String UTF8 = "UTF-8";
    public static final String CLAIMS = "claims";
    public static final String GUARD_CUSTOM_AUTH_FRONTEND_PATH = "guard.custom.auth.frontend.path";
    public static final String GUARD_DISABLE_INTERNAL_IDP = "guard.disable.internal.idp";
    public static final String DISABLE_INTERNAL_IDP = "disable_internal_idp";
    public static final String ADAPTER_ID = "adapter_id";
    public static final String CLOUDWATCH = "cloudwatch";
    public static final String GUARD_LOG_TARGET = "GUARD_LOG_TARGET";
    public static final String GUARD_VAULT_HOST_ENV_CONFIG_KEY = "GUARD_VAULT_HOST";
    public static final String GUARD_VAULT_HOST_CONFIG_KEY = "guard.vault.host";
    public static final String GUARD_VAULT_PORT_ENV_CONFIG_KEY = "GUARD_VAULT_PORT";
    public static final String GUARD_VAULT_PORT_CONFIG_KEY = "guard.vault.port";
    public static final String GUARD_VAULT_ROLE_CONFIG_KEY = "guard.vault.role";
    public static final String GUARD_VAULT_ROLE_ENV_CONFIG_KEY = "GUARD_VAULT_ROLE";
    public static final String GUARD_VAULT_SSL_CONFIG_KEY = "guard.vault.ssl";
    public static final String GUARD_VAULT_SSL_ENV_CONFIG_KEY = "GUARD_VAULT_SSL";
    public static final String GUARD_VAULT_PATH_CONFIG_KEY = "guard.vault.path";
    public static final String GUARD_VAULT_PATH_ENV_CONFIG_KEY = "GUARD_VAULT_PATH";
    public static final String AUDIT = "AUDIT";
    public static final String EVENT = "event";
    public static final String AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED";
    public static final String AUTHENTICATION_SUCCESS = "AUTHENTICATION_SUCCESS";
    public static final String USER_ID = "userId";
    public static final String CURRENT_CLIENT = "current_client";
    public static final String CURRENT_REDIRECT_URI = "current_redirect_uri";
    public static final String ADVANCED_ATTR = "advanced_attr";
    public static final String ONE_SHOT = "one_shot";
    public static final String ONE_SHOT_SCOPES = "one_shot_scopes";
    public static final String CONSENT_URL = "consent_url";
    public static final String CERT_SUBJECT_DN = "cert_subject_dn";
    public static final String CLIENT_ID_LIST_FOR_IMPLICIT_CONSENT = "client_id_list_for_implicit_consent";
    public static final String AUTHORIZED_FLOWS = "authorized_flows";
    public static final String OAUTH2_ERROR_CODE_INVALID_GRANT = "invalid_grant";


    private Constant() {
        //Hide public constructor
    }
}
