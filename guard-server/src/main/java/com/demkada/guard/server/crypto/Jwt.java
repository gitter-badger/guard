package com.demkada.guard.server.crypto;

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
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

class Jwt {

    private static final Logger LOGGER = LoggerFactory.getLogger(Jwt.class);


    private final Vertx vertx;
    private final JWSSigner signer;
    private final JWSVerifier verifier;

    Jwt(Vertx vertx, KeyPair keyPair) {
        this.vertx = vertx;
        this.signer = new RSASSASigner(keyPair.getPrivate());
        this.verifier = new RSASSAVerifier((RSAPublicKey) keyPair.getPublic());
    }

    void validateToken(Message<JsonObject> message) {
        vertx.<JsonObject>executeBlocking(f -> {
            try {
                String payload = message.body().getString(Constant.PAYLOAD);
                SignedJWT signedJWT = SignedJWT.parse(payload);
                if (signedJWT.verify(this.verifier)
                        && signedJWT.getJWTClaimsSet().getIssuer().equalsIgnoreCase(vertx.getOrCreateContext().config().getString(Constant.GUARD_JWT_ISSUER, Constant.GUARD))
                        && signedJWT.getJWTClaimsSet().getExpirationTime().after(new Date())) {
                    f.complete(new JsonObject(signedJWT.getPayload().toJSONObject().toJSONString()));
                }
                else {
                    f.fail("Invalid token");
                }
            } catch (ParseException e) {
                LOGGER.error("Unable to parse Token", e);
                f.fail(new GuardException(e));
            } catch (JOSEException e) {
                LOGGER.error("Unable to validate Token", e);
                f.fail(new GuardException(e));
            }
        }, ar -> {
            if (ar.succeeded()) {
                final JsonObject object = new JsonObject().put(Constant.RESPONSE, JsonObject.mapFrom(ar.result()));
                message.reply(object);
            }
            else {
                message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), ar.cause().getMessage());
            }
        });
    }

    void generateUserToken(Message<JsonObject> message) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.claim(Constant.AUTH_TIME, new Date())
                .claim(Constant.AUTH_METHOTH, AuthMethodRef.password.name())
                .claim(Constant.ACR, AuthContextClassRef.LOA2.name())
                .claim(Constant.GUARD_SUB_TYPE, PrincipalType.END_USER.name());

        if (message.body().containsKey(Constant.CLAIMS)) {
            message.body().getJsonObject(Constant.CLAIMS).getMap().forEach(builder::claim);
            if (!message.body().getJsonObject(Constant.CLAIMS).containsKey(Constant.EMAIL)) {
                builder.claim(Constant.EMAIL, message.body().getJsonObject(Constant.CLAIMS).getString(Constant.SUB));
            }
        }

        if (message.body().containsKey(Constant.USER)) {
            User user = Utils.sanitizeUser(message.body().getJsonObject(Constant.USER).mapTo(User.class));
            builder.subject(user.getSub())
                    .claim(Constant.GIVEN_NAME, user.getGivenName())
                    .claim(Constant.FAMILY_NAME, user.getFamilyName())
                    .claim(Constant.EMAIL, user.getEmail())
                    .claim(Constant.EMAIL_VERIFIED, user.isEmailVerified())
                    .claim(Constant.PHONE_NUMBER, user.getPhoneNumber())
                    .claim(Constant.PHONE_NUMBER_VERIFIED, user.isPhoneNumberVerified())
                    .claim(Constant.ADDRESS, user.getAddress())
                    .claim(Constant.ID_ORIGIN, user.getIdOrigin());
        }
        builder.issuer(vertx.getOrCreateContext().config().getString(Constant.GUARD_JWT_ISSUER, Constant.GUARD))
                .expirationTime(Date.from(new Date().toInstant().plus(message.body().getLong(Constant.EXP), ChronoUnit.MINUTES)));
        vertx.<String>executeBlocking(f -> {
            try {
                SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), builder.build());
                signedJWT.sign(this.signer);
                f.complete(signedJWT.serialize());
            } catch (JOSEException e) {
                f.fail(new GuardException(e));
            }
        }, ar -> {
            if (ar.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, ar.result()));
            }
            else {
                LOGGER.error("Unable to generate User Token", ar.cause());
                message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), ar.cause().getMessage());
            }
        });
    }

    void generateOAuth2Token(Message<JsonObject> message) {
        AccessToken accessToken = new AccessToken();
        accessToken.setSub(message.body().getJsonObject(Constant.PAYLOAD).getJsonObject("sub"));
        accessToken.setExp(message.body().getJsonObject(Constant.PAYLOAD).getLong("exp"));
        accessToken.setClientId(message.body().getJsonObject(Constant.PAYLOAD).getString("clientId"));
        Set<String> scopes = new HashSet<>();
        message.body().getJsonObject(Constant.PAYLOAD).getJsonArray("scopes").forEach(s -> scopes.add(new JsonObject((String) s).getString("name")));
        accessToken.setScopes(scopes);
        vertx.<JsonObject>executeBlocking(f -> {
            try {
                JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
                if (Objects.nonNull(message.body().getString(Constant.NONCE))) {
                    builder.claim(Constant.NONCE, message.body().getString(Constant.NONCE));
                }
                if (Objects.nonNull(message.body().getJsonObject("cnf"))) {
                    JSONObject jsonObject = new JSONObject();
                    jsonObject.put("x5t#S256", message.body().getJsonObject("cnf").getString("x5t#S256"));
                    builder.claim("cnf", jsonObject);
                }
                if (Objects.isNull(accessToken.getSub().getString("sub"))) {
                    accessToken.getSub().put("sub", accessToken.getSub().getString("email"));
                }
                accessToken.getSub().getMap().forEach((k,v) -> {
                    if (!"labels".equalsIgnoreCase(k)) {
                        builder.claim(k, v);
                    }
                });
                Date issueAt = new Date();
                builder.subject(PrincipalType.valueOf(accessToken.getSub().getString(Constant.GUARD_SUB_TYPE)).equals(PrincipalType.END_USER) ? accessToken.getSub().getString("sub") : accessToken.getClientId())
                        .issuer(vertx.getOrCreateContext().config().getString(Constant.GUARD_JWT_ISSUER, Constant.GUARD))
                        .jwtID(UUID.randomUUID().toString())
                        .expirationTime(new Date(issueAt.getTime() + accessToken.getExp() * 60000))
                        .claim(Constant.CLIENT_ID, accessToken.getClientId())
                        .claim(Constant.SCOPE, new JsonArray(new ArrayList<>(accessToken.getScopes())))
                        .claim(Constant.AUDIENCE, accessToken.getClientId())
                        .claim(Constant.IAT, issueAt);
                String kid;
                if (vertx.getOrCreateContext().config().containsKey(Constant.GUARD_KMIP_SERVER) && vertx.getOrCreateContext().config().getBoolean(Constant.GUARD_KMIP_SERVER)) {
                    kid = vertx.getOrCreateContext().config().getString(Constant.GUARD_KMIP_SERVER_RSA_PRIVATE_KEY);
                } else {
                    kid = vertx.getOrCreateContext().config().getString(Constant.GUARD_CRYPTO_RSA_KEYPAIR_ALIAS, "guard-rsa-keypair");
                }
                SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(), builder.build());
                signedJWT.sign(this.signer);
                if (vertx.getOrCreateContext().config().containsKey(Constant.GUARD_OAUTH2_OPAQUE_ACCESS_TOKEN) && vertx.getOrCreateContext().config().getBoolean(Constant.GUARD_OAUTH2_OPAQUE_ACCESS_TOKEN)) {
                    AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_STRING));
                    this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, new JsonObject().put(Constant.PAYLOAD, signedJWT.serialize()), options.get(), r -> {
                        if (r.succeeded()) {
                            JsonObject resp = (JsonObject) r.result().body();
                            f.complete(new JsonObject()
                                    .put(Constant.ACCESS_TOKEN, resp.getString(Constant.RESPONSE))
                                    .put(Constant.ID_TOKEN, signedJWT.serialize()));
                        }
                        else {
                            f.fail(r.cause());
                        }
                    });
                }
                else {
                    f.complete(new JsonObject()
                            .put(Constant.ACCESS_TOKEN, signedJWT.serialize())
                            .put(Constant.ID_TOKEN, signedJWT.serialize()));
                }
            } catch (JOSEException e) {
                f.fail(new GuardException(e));
            }
        }, ar -> {
            if (ar.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, ar.result()));
            }
            else {
                LOGGER.error("Unable to generate OAuth2 Token", ar.cause());
                message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), ar.cause().getMessage());
            }
        });
    }

    void validateEncryptedToken(Message<JsonObject> message) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_STRING));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, message.body(), options.get(), reply -> {
            if (reply.succeeded()) {
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_TOKEN));
                JsonObject response = (JsonObject) reply.result().body();
                this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, new JsonObject().put(Constant.PAYLOAD, response.getString(Constant.RESPONSE)), options.get(), r -> {
                    if (r.succeeded()) {
                        message.reply(r.result().body());
                    }
                    else {
                        message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), r.cause().getMessage());
                    }
                });
            }
            else {
                message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), reply.cause().getMessage());
            }
        });

    }

    void generateEncryptedUserToken(Message<JsonObject> message) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_USER_TOKEN));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, message.body(), options.get(), reply -> {
            if (reply.succeeded()) {
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_STRING));
                JsonObject response = (JsonObject) reply.result().body();
                this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, new JsonObject().put(Constant.PAYLOAD, response.getString(Constant.RESPONSE)), options.get(), r -> {
                    if (r.succeeded()) {
                        JsonObject resp = (JsonObject) r.result().body();
                        message.reply(resp);
                    }
                    else {
                        message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), r.cause().getMessage());
                    }
                });
            }
            else {
                message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), reply.cause().getMessage());
            }
        });

    }

}
