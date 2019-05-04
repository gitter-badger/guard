package com.demkada.guard.server.oauth2;

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


import com.demkada.guard.server.commons.model.*;
import com.demkada.guard.server.commons.utils.CassandraDriver;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.Utils;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.manager.AuthZCode_Manager;
import info.archinnov.achilles.generated.manager.RefreshToken_Manager;
import io.vertx.core.AsyncResult;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

class TokenService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenService.class);

    private static final String SERVER_ERROR_MESSAGE = "server_error for request by client: ";

    private final Vertx vertx;
    private final AuthZCode_Manager authZCodeManager;
    private final RefreshToken_Manager refreshTokenManager;

    TokenService(Vertx vertx) {
        this.vertx = vertx;
        authZCodeManager = ManagerFactoryBuilder_For_Guard
                .builder(CassandraDriver.getOrCreate(vertx.getOrCreateContext().config()).getCluster())
                .withDefaultKeyspaceName(Constant.GUARD)
                .doForceSchemaCreation(false)
                .build()
                .forAuthZCode();
        refreshTokenManager = ManagerFactoryBuilder_For_Guard
                .builder(CassandraDriver.getOrCreate(vertx.getOrCreateContext().config()).getCluster())
                .withDefaultKeyspaceName(Constant.GUARD)
                .doForceSchemaCreation(false)
                .build()
                .forRefreshToken();
    }


    void handle(RoutingContext context) {
        String input = context.getBodyAsString();
        if (Objects.nonNull(input)) {
            JsonObject body = Utils.convertUrlFormEncodedToJsonObject(input);
            GrantType grantType = null;
            try {
                grantType = GrantType.valueOf(body.getString(Constant.GRANT_TYPE));
            }
            catch (Exception e) {
                LOGGER.debug("invalid_request" + " provided by client: " + context.user().principal().getString(Constant.CLIENT_ID), new GuardException(e));
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR, "invalid_request").encode());
            }
            if (GrantType.client_credentials.equals(grantType)) {
                handleClientCredentialGrant(context, body);
            }
            else if (GrantType.refresh_token.equals(grantType)) {
                handleRefreshTokenGrant(context, body);
            }
            else if (GrantType.authorization_code.equals(grantType)) {
                String uri = body.getString(Constant.REDIRECT_URI);
                try {
                    uri = URLDecoder.decode(uri, "UTF-8");
                    handleAuthCodeGrant(context, body, uri);
                }
                catch (Exception e) {
                    LOGGER.debug("invalid_request" + " provided by client: " + context.user().principal().getString(Constant.CLIENT_ID), new GuardException(e));
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR, "invalid_request").encode());
                }
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR, "invalid_request").encode());
            }
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR, "invalid_request").encode());
        }

    }

    private void handleClientCredentialGrant(RoutingContext context, JsonObject body) {
        String scope = body.getString("scope");
        if (Objects.isNull(scope) || scope.isEmpty()) {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR, "scope not provided").encode());
        }
        else {
            final List<String> scopeName = Arrays.asList(scope.trim().split(" "));
            AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPES));
            AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.SCOPE_NAME, scopeName));
            vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                if (res.succeeded()) {
                    generateClientCredToken(context, options, entries, res);
                }
                else {
                    String uuid = UUID.randomUUID().toString();
                    LOGGER.error(uuid, res.cause());
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR, "Internal error").encode());
                }
            });
        }
    }

    private void generateClientCredToken(RoutingContext context, AtomicReference<DeliveryOptions> options, AtomicReference<JsonObject> entries, AsyncResult<Message<Object>> res) {
        JsonArray array = ((JsonObject) res.result().body()).getJsonArray(Constant.RESPONSE);
        Set<String> scopes = new HashSet<>();
        AtomicReference<String> x509Hash = new AtomicReference<>("");
        array.forEach(o -> {
            JsonObject object = (JsonObject) o;
            final Scope s = object.mapTo(Scope.class);
            if ((Objects.isNull(s.getAuthorizedFlows()) || s.getAuthorizedFlows().isEmpty()) || (s.getAuthorizedFlows().contains(GrantType.client_credentials))) {
                scopes.add(new JsonObject().put("name", s.getName()).encode());
                if (s.isMachineMFA()) {
                    x509Hash.set(validateMachineMFA(context, new JsonObject().put("caChain", s.getTrustCaChain()), context.user().principal()));
                }
                if (s.isRestricted() && !s.getClientIdList().contains(context.user().principal().getString(Constant.CLIENT_ID))) {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, "unauthorized client").encode());
                }
            }
        });

        AccessToken accessToken = new AccessToken(context.user().principal(), scopes, context.user().principal().getString(Constant.CLIENT_ID), 60L);
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_OAUTH2_TOKEN));
        JsonObject body = new JsonObject().put(Constant.PAYLOAD, JsonObject.mapFrom(accessToken));
        if (!x509Hash.get().isEmpty()) {
            body.put("cnf", new JsonObject().put("x5t#S256", x509Hash.get()));
        }
        entries.set(body);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), asyncResult -> {
            if (asyncResult.succeeded()) {
                JsonObject responseObject = ((JsonObject) asyncResult.result().body()).getJsonObject(Constant.RESPONSE);
                final JsonObject tokenResponse = new JsonObject().put(Constant.ACCESS_TOKEN, responseObject.getString(Constant.ACCESS_TOKEN))
                        .put(Constant.TOKEN_TYPE, Constant.BEARER)
                        .put(Constant.EXPIRE_IN, TimeUnit.SECONDS.convert(accessToken.getExp(), TimeUnit.MINUTES))
                        .put(Constant.SCOPE, new JsonArray(new ArrayList<>(scopes)));

                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                        .setStatusCode(200)
                        .putHeader(Constant.CACHE_CONTROL, Constant.NO_STORE)
                        .putHeader(Constant.PRAGMA, Constant.NO_CACHE)
                        .end(tokenResponse.encode());
            }
            else {
                String uuid = UUID.randomUUID().toString();
                LOGGER.error(uuid, asyncResult.cause());
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR_MESSAGE, "Internal error").encode());
            }
        });
    }

    private String validateMachineMFA(RoutingContext context, JsonObject s, JsonObject client) {
        String trustCaChain = "";
        if (Objects.nonNull(s.getString("caChain"))) {
            trustCaChain = s.getString("caChain");
        }
        else if (Objects.nonNull(context.user().principal().getString("cert"))){
            trustCaChain = context.user().principal().getString("cert");
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, "No trust store provided for machine MFA").encode());
        }
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            if (vertx.getOrCreateContext().config().containsKey(Constant.GUARD_CLIENT_CERT_HEADER) && Objects.nonNull(context.request().getHeader(vertx.getOrCreateContext().config().getString(Constant.GUARD_CLIENT_CERT_HEADER)))) {
                final X509Certificate clientCert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(new String(Base64.getDecoder().decode(context.request().getHeader(vertx.getOrCreateContext().config().getString(Constant.GUARD_CLIENT_CERT_HEADER)))).getBytes()));
                Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(new ByteArrayInputStream(trustCaChain.getBytes()));
                X509Certificate[] certs = new X509Certificate[certificates.size()];
                AtomicInteger i = new AtomicInteger();
                certificates.forEach(c -> certs[i.getAndIncrement()] = (X509Certificate) c);
                if (Utils.validateCaChain(clientCert, clientCert, client, certs)) {
                    return StringUtils.stripEnd(Base64.getUrlEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(clientCert.getEncoded())), "=");
                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, "Client cert not valid").encode());
                }
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, "Client cert not found").encode());
            }

        } catch (Exception e) {
            String uuid = UUID.randomUUID().toString();
            LOGGER.error(uuid, e);
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, "Can't not validate client certificate for machine-MFA").encode());
        }
        return "";
    }

    private void handleRefreshTokenGrant(RoutingContext context, JsonObject body) {
        String id = body.getString(Constant.REFRESH_TOKEN);
        vertx.<RefreshToken>executeBlocking(f -> {
            RefreshToken refreshToken = refreshTokenManager.crud().findById(id, context.user().principal().getString(Constant.CLIENT_ID)).get();
            refreshTokenManager.crud().deleteById(id, context.user().principal().getString(Constant.CLIENT_ID)).ifExists().execute();
            f.complete(refreshToken);
        }, r-> {
            if (r.succeeded() && Objects.nonNull(r.result())) {
                RefreshToken refreshToken = r.result();
                if (Objects.isNull(refreshToken.getScopes())) {
                    refreshToken.setScopes(new HashSet<>());
                }
                AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CONSENTS));
                AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject()
                        .put(Constant.SCOPE_NAME, new JsonArray(new ArrayList<>(refreshToken.getScopes())))
                        .put(Constant.USER_EMAIL, context.user().principal().getString(Constant.EMAIL))
                        .put(Constant.CLIENT_ID, refreshToken.getClientId()));
                vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries.get(), options.get(), ar -> {
                    if (ar.succeeded()) {
                        final Set<String> scopes = new HashSet<>();
                        JsonObject b = (JsonObject) ar.result().body();
                        JsonArray array = b.getJsonArray(Constant.RESPONSE);
                        refreshToken.getScopes().forEach(s -> {
                            if (array.stream().anyMatch(c -> new JsonObject(s).getString("name").equalsIgnoreCase(((JsonObject) c).getString("scopeName")))) {
                                scopes.add(s);
                            }
                        });
                        if (!scopes.isEmpty()) {
                            refreshToken.setScopes(scopes);
                            long ttl = refreshToken.getRefreshTokenTTL() - TimeUnit.MINUTES.convert(new Date().getTime() - refreshToken.getIssueAt().getTime(), TimeUnit.MILLISECONDS);
                            if (ttl > 0 ) {
                                JsonArray p = new JsonArray().add(refreshToken.getPrincipal());
                                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_STRING_SET));
                                entries.set(new JsonObject().put(Constant.PAYLOAD, p));
                                vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                                    if (reply.succeeded()) {
                                        String principal = ((JsonObject) reply.result().body()).getJsonArray(Constant.RESPONSE).getString(0);
                                        AtomicReference<String> x509Hash = new AtomicReference<>("");
                                        refreshToken.getScopes().forEach(o -> {
                                            JsonObject s = new JsonObject(o);
                                            if (s.containsKey("machineMFA") && s.getBoolean("machineMFA")) {
                                                x509Hash.set(validateMachineMFA(context, s, context.user().principal()));
                                            }
                                        });
                                        AccessToken accessToken = new AccessToken(new JsonObject(principal), refreshToken.getScopes(), refreshToken.getClientId(), 15L);
                                        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_OAUTH2_TOKEN));
                                        final JsonObject object = new JsonObject().put(Constant.PAYLOAD, JsonObject.mapFrom(accessToken));
                                        if (!x509Hash.get().isEmpty()) {
                                            object.put("cnf", new JsonObject().put("x5t#S256", x509Hash.get()));
                                        }
                                        entries.set(object);
                                        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), asyncResult -> {
                                            if (asyncResult.succeeded()) {
                                                JsonObject responseObject = ((JsonObject) asyncResult.result().body()).getJsonObject(Constant.RESPONSE);
                                                final JsonObject tokenResponse = new JsonObject().put(Constant.ACCESS_TOKEN, responseObject.getString(Constant.ACCESS_TOKEN))
                                                        .put(Constant.TOKEN_TYPE, Constant.BEARER)
                                                        .put(Constant.EXPIRE_IN, TimeUnit.SECONDS.convert(accessToken.getExp(), TimeUnit.MINUTES));

                                                refreshToken.setId(UUID.randomUUID().toString());
                                                refreshToken.setIssueAt(new Date());
                                                refreshToken.setRefreshTokenTTL((int) ttl);
                                                vertx.executeBlocking(f -> {
                                                    refreshTokenManager.crud().insert(refreshToken).usingTimeToLive((int) TimeUnit.SECONDS.convert(ttl, TimeUnit.MINUTES)).execute();
                                                    f.complete();
                                                }, result -> {
                                                    tokenResponse.put(Constant.REFRESH_TOKEN, refreshToken.getId());
                                                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                                                            .setStatusCode(200)
                                                            .putHeader(Constant.CACHE_CONTROL, Constant.NO_STORE)
                                                            .putHeader(Constant.PRAGMA, Constant.NO_CACHE)
                                                            .end(tokenResponse.encode());
                                                });
                                            }
                                            else {
                                                String uuid = UUID.randomUUID().toString();
                                                LOGGER.error(uuid, asyncResult.cause());
                                                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR, Constant.OAUTH2_ERROR_CODE_SERVER_ERROR).encode());
                                            }
                                        });
                                    }
                                    else {
                                        LOGGER.debug(SERVER_ERROR_MESSAGE + context.user().principal().getString(Constant.CLIENT_ID), new GuardException(reply.cause()));
                                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR, Constant.OAUTH2_ERROR_CODE_SERVER_ERROR).encode());
                                    }
                                });
                            }
                            else {
                                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                                        .setStatusCode(401)
                                        .end(new JsonObject().put(Constant.ERROR, Constant.OAUTH2_ERROR_CODE_INVALID_GRANT).encode());
                            }
                        }
                        else {
                            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                                    .setStatusCode(401)
                                    .end(new JsonObject().put(Constant.ERROR, Constant.OAUTH2_ERROR_CODE_INVALID_GRANT).encode());
                        }
                    }
                    else {
                        String uuid = UUID.randomUUID().toString();
                        LOGGER.error(uuid, ar.cause());
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR, Constant.OAUTH2_ERROR_CODE_SERVER_ERROR).encode());
                    }
                });
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                        .setStatusCode(401)
                        .end(new JsonObject().put(Constant.ERROR, Constant.OAUTH2_ERROR_CODE_INVALID_GRANT).encode());
            }
        });
    }

    private void handleAuthCodeGrant(RoutingContext context, JsonObject body, String uri) {
        String code = body.getString(Constant.CODE);
        vertx.<AuthZCode>executeBlocking(f -> {
            AuthZCode authZCode = authZCodeManager.crud().findById(code, context.user().principal().getString(Constant.CLIENT_ID)).get();
            authZCodeManager.crud().deleteById(code, context.user().principal().getString(Constant.CLIENT_ID)).ifExists().execute();
            f.complete(authZCode);
        }, r-> {
            if (r.succeeded()) {
                AuthZCode authZCode = r.result();
                if (uri.equalsIgnoreCase(authZCode.getRedirectUri())) {
                    JsonArray p = new JsonArray().add(authZCode.getPrincipal());
                    AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_STRING_SET));
                    AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, p));
                    vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                        if (reply.succeeded()) {
                            JsonObject response = (JsonObject) reply.result().body();
                            AtomicReference<String> x509Hash = new AtomicReference<>("");
                            authZCode.setPrincipal(response.getJsonArray(Constant.RESPONSE).getString(0));
                            authZCode.getScopes().forEach(o -> {
                                JsonObject s = new JsonObject(o);
                                if (s.containsKey("machineMFA") && s.getBoolean("machineMFA")) {
                                    x509Hash.set(validateMachineMFA(context, s, context.user().principal()));
                                }
                            });
                            AccessToken accessToken = new AccessToken(new JsonObject(authZCode.getPrincipal()), authZCode.getScopes(), authZCode.getClientId(), 15L);
                            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_OAUTH2_TOKEN));
                            final JsonObject object = new JsonObject().put(Constant.PAYLOAD, JsonObject.mapFrom(accessToken));
                            if (Objects.nonNull(authZCode.getNonce()) && authZCode.getScopes().stream().anyMatch(s -> new JsonObject(s).getString("name").equalsIgnoreCase(Constant.OPENID))) {
                                object.put(Constant.NONCE, authZCode.getNonce());
                            }
                            if (!x509Hash.get().isEmpty()) {
                                object.put("cnf", new JsonObject().put("x5t#S256", x509Hash.get()));
                            }
                            entries.set(object);
                            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), asyncResult -> {
                                if (asyncResult.succeeded()) {
                                    JsonObject responseObject = ((JsonObject) asyncResult.result().body()).getJsonObject(Constant.RESPONSE);
                                    final JsonObject tokenResponse = new JsonObject().put(Constant.ACCESS_TOKEN, responseObject.getString(Constant.ACCESS_TOKEN))
                                            .put(Constant.TOKEN_TYPE, Constant.BEARER)
                                            .put(Constant.EXPIRE_IN, TimeUnit.SECONDS.convert(accessToken.getExp(), TimeUnit.MINUTES));
                                    if (Objects.nonNull(authZCode.getState())) {
                                        tokenResponse.put(Constant.STATE, authZCode.getState());
                                    }
                                    if (authZCode.getScopes().stream().anyMatch(s -> new JsonObject(s).getString("name").equalsIgnoreCase(Constant.OPENID))) {
                                        tokenResponse.put(Constant.ID_TOKEN, responseObject.getString(Constant.ID_TOKEN));
                                    }

                                    Set<String> refreshTokenScopes = new CopyOnWriteArraySet<>(authZCode.getScopes());
                                    if (Objects.nonNull(authZCode.getOneShotScopes())) {
                                        refreshTokenScopes.forEach(s -> {
                                            if (authZCode.getOneShotScopes().contains(new JsonObject(s).getString("name"))) {
                                                refreshTokenScopes.remove(s);
                                            }
                                        });
                                    }

                                    RefreshToken refreshToken = new RefreshToken();
                                    refreshToken.setId(UUID.randomUUID().toString());
                                    refreshToken.setClientId(authZCode.getClientId());
                                    refreshToken.setClientName(authZCode.getClientName());
                                    refreshToken.setIssueAt(new Date());
                                    refreshToken.setRefreshTokenTTL(authZCode.getRefreshTokenTTL());
                                    refreshToken.setScopes(refreshTokenScopes);
                                    JsonArray payload = new JsonArray().add(authZCode.getPrincipal());
                                    options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_STRING_SET));
                                    entries.set(new JsonObject().put(Constant.PAYLOAD, payload));
                                    vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), ciphered -> {
                                        if (ciphered.succeeded()) {
                                            refreshToken.setPrincipal(((JsonObject) ciphered.result().body()).getJsonArray(Constant.RESPONSE).getString(0));
                                            vertx.executeBlocking(f -> {
                                                refreshTokenManager.crud().insert(refreshToken).usingTimeToLive((int) TimeUnit.SECONDS.convert((long) authZCode.getRefreshTokenTTL(), TimeUnit.MINUTES)).execute();
                                                f.complete();
                                            }, result -> {
                                                tokenResponse.put(Constant.REFRESH_TOKEN, refreshToken.getId());
                                                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                                                        .setStatusCode(200)
                                                        .putHeader(Constant.CACHE_CONTROL, Constant.NO_STORE)
                                                        .putHeader(Constant.PRAGMA, Constant.NO_CACHE)
                                                        .end(tokenResponse.encode());
                                            });

                                        }
                                        else {
                                            String uuid = UUID.randomUUID().toString();
                                            LOGGER.error(uuid, asyncResult.cause());
                                            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR_MESSAGE, "Internal error").encode());
                                        }
                                    });
                                }
                                else {
                                    String uuid = UUID.randomUUID().toString();
                                    LOGGER.error(uuid, asyncResult.cause());
                                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR_MESSAGE, "Internal error").encode());
                                }
                            });
                        }
                        else {
                            LOGGER.debug(SERVER_ERROR_MESSAGE + authZCode.getClientId(), new GuardException(reply.cause()));
                            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR_MESSAGE, "server_error").encode());
                        }
                    });

                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "unauthorized_client").encode());
                }
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "unauthorized_client").encode());
            }
        });
    }


}
