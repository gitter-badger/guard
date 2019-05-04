package com.demkada.guard.server.auth;

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


import com.demkada.guard.server.commons.model.Adapter;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.Utils;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.vertx.core.AsyncResult;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

class OIDCAdapter {

    private final Vertx vertx;
    private static final Logger LOGGER = LoggerFactory.getLogger(OIDCAdapter.class);

    OIDCAdapter(Vertx vertx) {
        this.vertx = vertx;
    }

    void login(RoutingContext context) {
        String input = context.getBodyAsString();
        if (Objects.nonNull(input)) {
            JsonObject entries = Utils.convertUrlFormEncodedToJsonObject(input);
            String id = entries.getString("adapter_id");
            String idToken = entries.getString("id_token");
            String state = entries.getString("state");
            String error = entries.getString("error");
            if (Objects.nonNull(id) && Objects.nonNull(idToken) && Objects.nonNull(state)) {
                DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_ADAPTER_BY_ID);
                JsonObject payload = new JsonObject().put(Constant.ID, id);
                vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, payload, options, reply -> {
                    if (reply.succeeded()) {
                        authenticateUser(context, reply, idToken, state);
                    }
                    else {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
                    }
                });
            }
            else if (Objects.nonNull(id) && Objects.nonNull(error) && Objects.nonNull(state) && Objects.nonNull(context.getCookie(Constant.GUARD_ADAPTER_NONCE))) {
                JsonObject nonce = new JsonObject(Buffer.buffer(Base64.getDecoder().decode(context.getCookie(Constant.GUARD_ADAPTER_NONCE).getValue())));
                if (state.equals(nonce.getString(Constant.STATE))) {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                            .setStatusCode(200)
                            .end(new JsonObject().put(Constant.ORIGINAL_URL, nonce.getString("redirect_uri") + "#error=" + error).encode());
                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
                }
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end();
            }
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
        }

    }

    private void authenticateUser(RoutingContext context, AsyncResult<Message<Object>> reply, String idToken, String state) {
        Adapter adapter = ((JsonObject) reply.result().body()).getJsonObject(Constant.RESPONSE).mapTo(Adapter.class);
        validateIdToken(vertx, context, adapter, idToken, state);
    }

    private void validateIdToken(Vertx vertx, RoutingContext context, Adapter adapter, String idToken, String state) {
        if (3 == idToken.split("\\.").length) {
            authenticateUserWithJwt(vertx, context, adapter, idToken, state);
        }
        else if (5 == idToken.split("\\.").length) {
            AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_STRING));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, new JsonObject().put(Constant.PAYLOAD, idToken), options.get(), reply -> {
                if (reply.succeeded()) {
                    authenticateUserWithJwt(vertx, context, adapter, ((JsonObject) reply.result().body()).getString(Constant.RESPONSE), state);
                }
                else {
                    MDC.put(Constant.TYPE, Constant.AUDIT);
                    LOGGER.error(new JsonObject().put(Constant.EVENT, Constant.AUTHENTICATION_FAILED).put("adapter", adapter.getName()).put("message", "Unable to decrypt JWE token").encode(), reply.cause());
                    MDC.remove(Constant.TYPE);
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
                }
            });
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
        }
    }

    private void authenticateUserWithJwt(Vertx vertx, RoutingContext context, Adapter adapter, String idToken, String state) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(adapter.getPublicKey()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            SignedJWT jwt = SignedJWT.parse(idToken);
            if (jwt.verify(new RSASSAVerifier((RSAPublicKey) keyFactory.generatePublic(keySpec))) && Objects.nonNull(context.getCookie(Constant.GUARD_ADAPTER_NONCE))) {
                if (context.getCookie(Constant.GUARD_ADAPTER_NONCE).getValue().equals(jwt.getJWTClaimsSet().getStringClaim(Constant.NONCE))) {
                    JsonObject nonce = new JsonObject(Buffer.buffer(Base64.getDecoder().decode(jwt.getJWTClaimsSet().getStringClaim(Constant.NONCE))));
                    if (state.equals(nonce.getString(Constant.STATE))) {
                        logUserIn(vertx, context, adapter, jwt, nonce);
                    }
                    else {
                        if (LOGGER.isWarnEnabled()) {
                            MDC.put(Constant.TYPE, Constant.AUDIT);
                            LOGGER.warn(new JsonObject().put(Constant.EVENT, Constant.AUTHENTICATION_FAILED).put("adapter", adapter.getName()).put("message", "invalid state").put(Constant.USER_ID, jwt.getJWTClaimsSet().getSubject()).encode());
                            MDC.remove(Constant.TYPE);
                        }
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
                    }
                }
                else {
                    if (LOGGER.isWarnEnabled()) {
                        MDC.put(Constant.TYPE, Constant.AUDIT);
                        LOGGER.warn(new JsonObject().put(Constant.EVENT, Constant.AUTHENTICATION_FAILED).put("adapter", adapter.getName()).put("message", "invalid nonce").put(Constant.USER_ID, jwt.getJWTClaimsSet().getSubject()).encode());
                        MDC.remove(Constant.TYPE);
                    }
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
                }
            }
            else {
                if (LOGGER.isWarnEnabled()) {
                    MDC.put(Constant.TYPE, Constant.AUDIT);
                    LOGGER.warn(new JsonObject().put(Constant.EVENT, Constant.AUTHENTICATION_FAILED).put("adapter", adapter.getName()).put("message", "Invalid signature for provided JWT").put(Constant.USER_ID, jwt.getJWTClaimsSet().getSubject()).encode());
                    MDC.remove(Constant.TYPE);
                }
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
            }
        } catch (Exception e) {
            if (LOGGER.isWarnEnabled()) {
                MDC.put(Constant.TYPE, Constant.AUDIT);
                LOGGER.warn(new JsonObject().put(Constant.EVENT, Constant.AUTHENTICATION_FAILED).put("adapter", adapter.getName()).put("message", "Unable to verify JWT").encode(), new GuardException(e));
                MDC.remove(Constant.TYPE);
            }
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
        }
    }

    private void logUserIn(Vertx vertx, RoutingContext context, Adapter adapter, SignedJWT jwt, JsonObject nonce) throws ParseException {
        JsonObject claims = new JsonObject(jwt.getJWTClaimsSet().toString()).put(Constant.ID_ORIGIN, adapter.getAdapterUrl());
        claims.remove("jti");
        claims.remove("nonce");
        claims.remove("nbf");
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.CLAIMS, claims).put(Constant.EXP, 720L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded()) {
                Cookie cookie = Cookie.cookie(vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_NAME, Constant.GUARD), ((JsonObject) reply.result().body()).getString(Constant.RESPONSE));
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                cookie.setSecure(true);
                cookie.setDomain(vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_DOMAIN, context.request().host().split(":")[0]));
                context.addCookie(cookie);
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                        .setStatusCode(200)
                        .end(new JsonObject().put(Constant.ORIGINAL_URL, nonce.getString(Constant.ORIGINAL_URL)).encode());
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
            }
        });
    }
}
