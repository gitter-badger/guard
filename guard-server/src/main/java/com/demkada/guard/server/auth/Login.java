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


import com.demkada.guard.server.commons.model.User;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.StringHashUtil;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.UUID;

class Login {

    private static final Logger LOGGER = LoggerFactory.getLogger(Login.class);

    private final Vertx vertx;

    Login(Vertx vertx) {
        this.vertx = vertx;
    }

    void handle(RoutingContext context) {
        JsonObject entries = context.getBodyAsJson();
        if (entries.containsKey(Constant.EMAIL)) {
            DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL);
            vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries, options, reply -> {
                if (reply.succeeded()) {
                    User user = new JsonObject(reply.result().body().toString()).getJsonObject(Constant.RESPONSE).mapTo(User.class);
                    if (user.isEmailVerified()) {
                        StringHashUtil.validatePassword(vertx, entries.getString(Constant.PASS), user.getPwd(), generateToken(context, user));
                    }
                    else if (user.isDisable()) {
                        JsonObject body = new JsonObject().put(Constant.HTTP_STATUS_CODE, 401).put(Constant.ERROR_MESSAGE, "Your account is disable");
                        MDC.put(Constant.TYPE, Constant.AUDIT);
                        LOGGER.warn(body.put(Constant.EVENT, Constant.AUTHENTICATION_FAILED).put(Constant.USER_ID, user.getEmail()).encode());
                        MDC.remove(Constant.TYPE);
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
                    }
                    else {
                        JsonObject body = new JsonObject().put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, "Email has not been verified yet!");
                        MDC.put(Constant.TYPE, Constant.AUDIT);
                        LOGGER.warn(body.put(Constant.EVENT, Constant.AUTHENTICATION_FAILED).put(Constant.USER_ID, user.getEmail()).encode());
                        MDC.remove(Constant.TYPE);
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(body.encode());
                    }
                }
                else {
                    rejectRequest(context, entries);
                }
            });
        }
        else {
            rejectRequest(context, entries);
        }
    }

    private void rejectRequest(RoutingContext context, JsonObject entries) {
        JsonObject body = new JsonObject().put(Constant.HTTP_STATUS_CODE, 401).put(Constant.ERROR_MESSAGE, "Invalid credentials");
        MDC.put(Constant.TYPE, Constant.AUDIT);
        if (LOGGER.isWarnEnabled()) {
            LOGGER.warn(body.put(Constant.EVENT, Constant.AUTHENTICATION_FAILED).put(Constant.USER_ID, entries.getString(Constant.EMAIL)).put(Constant.ERROR_MESSAGE, "Invalid email").encode());
        }
        MDC.remove(Constant.TYPE);
        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end(body.encode());
    }

    private Handler<AsyncResult<Boolean>> generateToken(RoutingContext context, User user) {
        return r -> {
            if (r.succeeded() && r.result()) {
                User u = Utils.sanitizeUser(user);
                DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
                JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(u)).put(Constant.EXP, 720L);
                this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, reply -> {
                    if (reply.succeeded()) {
                        JsonObject response = (JsonObject) reply.result().body();
                        Cookie cookie = Cookie.cookie(vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_NAME, Constant.GUARD), response.getString(Constant.RESPONSE));
                        cookie.setHttpOnly(true);
                        cookie.setPath("/");
                        cookie.setSecure(true);
                        cookie.setDomain(vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_DOMAIN, context.request().host().split(":")[0]));
                        context.addCookie(cookie);
                        JsonObject body = new JsonObject().put(Constant.HTTP_STATUS_CODE, 200);
                        MDC.put(Constant.TYPE, Constant.AUDIT);
                        LOGGER.info(body.put(Constant.EVENT, Constant.AUTHENTICATION_SUCCESS).put(Constant.USER_ID, user.getEmail()).encode());
                        MDC.remove(Constant.TYPE);
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
                    }
                    else {
                        String uuid = UUID.randomUUID().toString();
                        LOGGER.error(uuid, reply.cause());
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR_MESSAGE, "Internal error").encode());
                    }
                });
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 401).put(Constant.ERROR_MESSAGE, "Invalid credentials").encode());
            }
        };
    }
}
