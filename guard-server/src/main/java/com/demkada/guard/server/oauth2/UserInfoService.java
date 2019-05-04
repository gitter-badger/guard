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


import com.demkada.guard.server.commons.utils.Constant;
import io.vertx.core.AsyncResult;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

class UserInfoService {

    private final Vertx vertx;
    private static final String ERROR_RESPONSE = "WWW-Authenticate: error=\"invalid_token\"";

    UserInfoService(Vertx vertx) {
        this.vertx = vertx;
    }

    void handle(RoutingContext context) {
        String bearerToken = context.request().getHeader("Authorization");
        AtomicReference<DeliveryOptions> options = new AtomicReference<>();
        AtomicReference<JsonObject> entries = new AtomicReference<>();
        if (Objects.nonNull(bearerToken) && 2 == bearerToken.split(" ").length && Objects.nonNull(bearerToken.split(" ")[1]) && !bearerToken.split(" ")[1].isEmpty()) {
            String token = bearerToken.split(" ")[1];
            switch (token.split("\\.").length) {
                case 5:
                    options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN));
                    entries.set(new JsonObject().put(Constant.PAYLOAD, token));
                    this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> handleUserInfo(context, reply));
                    break;
                case 3:
                    options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_TOKEN));
                    entries.set(new JsonObject().put(Constant.PAYLOAD, token));
                    this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> handleUserInfo(context, reply));
                    break;
                default:
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end(ERROR_RESPONSE);
                    break;
            }
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end(ERROR_RESPONSE);
        }
    }

    private void handleUserInfo(RoutingContext context, AsyncResult<Message<Object>> reply) {
        if (reply.succeeded()) {
            JsonObject resp = ((JsonObject) reply.result().body()).getJsonObject(Constant.RESPONSE);
            if (resp.getJsonArray(Constant.SCOPE).contains("openid")) {
                resp.remove("jti");
                resp.remove("scope");
                resp.remove("guard_sub_type");
                resp.remove("exp");
                resp.remove("iat");
                resp.remove("nonce");
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(resp.encode());
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end(ERROR_RESPONSE);
            }
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end(ERROR_RESPONSE);
        }
    }
}
