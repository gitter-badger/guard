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


import com.demkada.guard.server.commons.model.InternalScope;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class NativeAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(NativeAdapter.class);
    private final Vertx vertx;

    NativeAdapter(Vertx vertx) {
        this.vertx = vertx;
    }

    void login(RoutingContext context) {
        context.user().isAuthorized(InternalScope.GUARD_GENERATE_USER_TOKEN.name(), ar -> {
            if (ar.succeeded()) {
                JsonObject body = context.getBodyAsJson();
                if (body.containsKey(Constant.SUB) && !body.getString(Constant.SUB).isEmpty()) {
                    if (!body.containsKey(Constant.EMAIL) || body.getString(Constant.EMAIL).isEmpty()) {
                        body.put(Constant.EMAIL, body.getString(Constant.SUB));
                    }
                    generateToken(context, body);
                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end();
                }
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
            }
        });
    }

    private void generateToken(RoutingContext context, JsonObject body) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.CLAIMS, body).put(Constant.EXP, 720L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded()) {
                JsonObject response = new JsonObject()
                        .put("guard_cookie_value", ((JsonObject) reply.result().body()).getString(Constant.RESPONSE))
                        .put("guard_cookie_name", vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_NAME, Constant.GUARD))
                        .put("guard_cookie_domain", vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_DOMAIN, context.request().host().split(":")[0]));

                context.response()
                        .putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                        .setStatusCode(200)
                        .end(response.encode());
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }
}