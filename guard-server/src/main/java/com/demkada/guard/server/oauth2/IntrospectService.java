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
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.AsyncResult;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

class IntrospectService {

    private static final Logger LOGGER = LoggerFactory.getLogger(IntrospectService.class);

    private final Vertx vertx;


    IntrospectService(Vertx vertx) {
        this.vertx = vertx;
    }

    void handle(RoutingContext context) {
        String input = context.getBodyAsString();
        if (Objects.nonNull(input)) {
            String token = Utils.convertUrlFormEncodedToJsonObject(input).getString("token");
            AtomicReference<DeliveryOptions> options = new AtomicReference<>();
            AtomicReference<JsonObject> entries = new AtomicReference<>();
            if (Objects.nonNull(token)) {
                if (5 == token.split("\\.").length) {
                    options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN));
                    entries.set(new JsonObject().put(Constant.PAYLOAD, token));
                    this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                        handleIntrospectionResponse(context, reply);
                    });
                }
                else if (3 == token.split("\\.").length) {
                    options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_TOKEN));
                    entries.set(new JsonObject().put(Constant.PAYLOAD, token));
                    this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                        handleIntrospectionResponse(context, reply);
                    });
                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(new JsonObject().put(Constant.ACTIVE, false).encode());
                }
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "invalid_request").encode());
            }
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "invalid_request").encode());
        }
    }

    private void handleIntrospectionResponse(RoutingContext context, AsyncResult<Message<Object>> reply) {
        if (reply.succeeded()) {
            JsonObject resp = ((JsonObject) reply.result().body()).getJsonObject(Constant.RESPONSE);
            String scope = (String) resp.getJsonArray(Constant.SCOPE).getList().stream().collect(Collectors.joining(" "));
            resp.put(Constant.ACTIVE, true);
            resp.put(Constant.SCOPE, scope);
            resp.put(Constant.USERNAME, resp.getString(Constant.SUB));
            resp.put(Constant.TOKEN_TYPE, Constant.ACCESS_TOKEN);
            resp.remove("nonce");
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(resp.encode());
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(new JsonObject().put(Constant.ACTIVE, false).encode());
        }
    }
}
