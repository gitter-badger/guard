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
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.StringHashUtil;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import static com.demkada.guard.server.commons.utils.Utils.validateUserToken;

class AuthHandler {

    private final Vertx vertx;

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthHandler.class);

    AuthHandler(Vertx vertx) {
        this.vertx = vertx;
    }

    void checkOAuth2Client(RoutingContext context) {
        String clientId = context.request().getParam("client_id");
        if (!Utils.isStrEmpty(clientId)) {
            String redirectUri = context.request().getParam("redirect_uri");
            AtomicReference<DeliveryOptions> options = new AtomicReference<>();
            AtomicReference<JsonObject> entries = new AtomicReference<>();
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENT_BY_ID));
            entries.set(new JsonObject().put(Constant.CLIENT_ID, clientId));
            vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries.get(), options.get(), result -> {
                if (result.succeeded()) {
                    JsonObject b = (JsonObject) result.result().body();
                    Client c = b.getJsonObject(Constant.RESPONSE).mapTo(Client.class);
                    if (Utils.isStrEmpty(redirectUri) && Objects.nonNull(c.getRedirectUris()) && 1 == c.getRedirectUris().size()) {
                        context.put(Constant.CURRENT_CLIENT, c);
                        context.put(Constant.CURRENT_REDIRECT_URI, c.getRedirectUris().toArray()[0]);
                        context.next();
                    }
                    else if (!Utils.isStrEmpty(redirectUri) && Objects.nonNull(c.getRedirectUris()) && c.getRedirectUris().contains(redirectUri)) {
                        context.put(Constant.CURRENT_CLIENT, c);
                        context.put(Constant.CURRENT_REDIRECT_URI, redirectUri);
                        context.next();
                    }
                    else {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 401).put(Constant.ERROR_MESSAGE, "invalid redirect_uri").encode());
                    }
                }
                else {
                    LOGGER.debug(result.cause().getMessage() + " " + clientId, new GuardException(result.cause()));
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 401).put(Constant.ERROR_MESSAGE, "unknown client application").encode());
                }
            });
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "client_id is not provided").encode());
        }
    }

    void handleEndUserCookie(RoutingContext context) {
        Cookie cookieToken = context.getCookie(vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_NAME, Constant.GUARD));
        if(Objects.nonNull(cookieToken) && !cookieToken.getValue().isEmpty()) {
            checkCookieCredentials(context, cookieToken.getValue());
        }
        else {
            Utils.redirectToLoginPage(vertx, context);
        }
    }



    void handleClientBasicAuthentication(RoutingContext context) {
        String basicToken = context.request().getHeader("Authorization");
        if (Objects.nonNull(basicToken) && 2 == basicToken.split(" ").length && Objects.nonNull(basicToken.split(" ")[1]) && !basicToken.split(" ")[1].isEmpty()) {
            checkBasicCredentials(context, basicToken.split(" ")[1]);
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
        }
    }
    private void checkCookieCredentials(RoutingContext context, String token) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.PAYLOAD, token);
        validateUserToken(vertx, context, options, entries);
    }


    private void checkBasicCredentials(RoutingContext context, String token) {
        String decodeCreds = new String(Base64.getDecoder().decode(token));
        final String[] creds = decodeCreds.split(":", 2);
        if (2 == creds.length) {
            DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENT_BY_ID);
            JsonObject entries = new JsonObject().put(Constant.CLIENT_ID, creds[0]);
            vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, res -> {
                if (res.succeeded()) {
                    JsonObject body = (JsonObject) res.result().body();
                    Client c = body.getJsonObject(Constant.RESPONSE).mapTo(Client.class);
                    StringHashUtil.validatePassword(vertx, creds[1], c.getSecret(), asyncResult -> {
                        if (asyncResult.succeeded() && asyncResult.result() && !c.isDisable()) {
                            c.setSecret(null);
                            GuardPrincipal principal = new GuardPrincipal(JsonObject.mapFrom(c), PrincipalType.APP);
                            principal.addClaim(Constant.ID_ORIGIN, Constant.GUARD);
                            principal.addClaim(Constant.AUTH_TIME, new Date().getTime());
                            principal.addClaim(Constant.AUTH_METHOTH, AuthMethodRef.password.name());
                            principal.addClaim(Constant.ACR, AuthContextClassRef.LOA2.name());
                            context.setUser(principal);
                            context.next();
                        }
                        else {
                            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
                        }
                    });
                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
                }
            });
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
        }
    }
}
