package com.demkada.guard.server;
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
import com.demkada.guard.server.commons.model.PrincipalType;
import com.demkada.guard.server.commons.model.GuardPrincipal;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.RoutingContext;

import java.util.Objects;

public class AuthHandler {

    private final Vertx vertx;
    private final boolean redirectForAuthN;

    public AuthHandler(Vertx vertx) {
        this.vertx = vertx;
        this.redirectForAuthN = false;
    }

    public AuthHandler(Vertx vertx, boolean redirectForAuthN) {
        this.vertx = vertx;
        this.redirectForAuthN = redirectForAuthN;
    }

    public void handle(RoutingContext context) {
        String bearerToken = context.request().getHeader("Authorization");
        Cookie cookieToken = context.getCookie(vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_NAME, Constant.GUARD));
        if(Objects.nonNull(cookieToken) && !cookieToken.getValue().isEmpty()) {
            checkUserToken(context, cookieToken.getValue());
        }
        else if (Objects.nonNull(bearerToken) && 2 == bearerToken.split(" ").length && Objects.nonNull(bearerToken.split(" ")[1]) && !bearerToken.split(" ")[1].isEmpty()) {
            checkAppToken(context, bearerToken.split(" ")[1]);
        }
        else if (this.redirectForAuthN) {
            Utils.redirectToLoginPage(vertx, context);
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
        }
    }

    private void checkAppToken(RoutingContext context, String token) {
        DeliveryOptions options = new DeliveryOptions();
        if (vertx.getOrCreateContext().config().containsKey(Constant.GUARD_OAUTH2_OPAQUE_ACCESS_TOKEN) && vertx.getOrCreateContext().config().getBoolean(Constant.GUARD_OAUTH2_OPAQUE_ACCESS_TOKEN)) {
            options.addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN);
        }
        else {
            options.addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_TOKEN);
        }
        JsonObject entries = new JsonObject().put(Constant.PAYLOAD, token);
        vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded()) {
                JsonObject resp = (JsonObject) reply.result().body();
                GuardPrincipal principal = new GuardPrincipal(resp.getJsonObject(Constant.RESPONSE), PrincipalType.APP);
                context.setUser(principal);
                context.next();
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
            }
        });
    }

    private void checkUserToken(RoutingContext context, String token) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.PAYLOAD, token);
        Utils.validateUserToken(vertx, context, options, entries);
    }
}
