package com.demkada.guard.server.adapters;

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
import com.demkada.guard.server.commons.model.AdapterType;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

class AdapterService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AdapterService.class);

    private final Vertx vertx;

    AdapterService(Vertx vertx) {
        this.vertx = vertx;
    }

    public void createAdapter(RoutingContext context) {
        JsonObject body = context.getBodyAsJson();
        Adapter adapter = body.mapTo(Adapter.class);
        if (isValid(adapter)) {
            adapter.setId(UUID.randomUUID().toString());
            AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_ADAPTER));
            AtomicReference<JsonObject> message = new AtomicReference<>(new JsonObject().put(Constant.ADAPTER, JsonObject.mapFrom(adapter)));
            vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, message.get(), options.get(), r -> {
                if (r.succeeded() && Objects.nonNull(r.result())) {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(201).end(JsonObject.mapFrom(adapter).encode());
                }
                else {
                    Utils.handleServerError(context, LOGGER, r.cause());
                }
            });
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "invalid input").encode());
        }
    }

    public void getAdapters(RoutingContext context) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_ADAPTERS);
        JsonObject entries = new JsonObject();
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded()) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(((JsonObject) reply.result().body()).getJsonArray(Constant.RESPONSE).encode());
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    public void getAdapterById(RoutingContext context) {
        String id = context.pathParam("id");
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_ADAPTER_BY_ID);
        JsonObject entries = new JsonObject().put(Constant.ID, id);
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded()) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(((JsonObject) reply.result().body()).getJsonObject(Constant.RESPONSE).encode());
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
            }
        });
    }

    public void updateAdapter(RoutingContext context) {
        String id = context.pathParam("id");
        JsonObject b = context.getBodyAsJson();
        Adapter actual = b.mapTo(Adapter.class);
        actual.setId(id);
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_ADAPTER_BY_ID));
        JsonObject entries = new JsonObject().put(Constant.ID, actual.getId());
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries, options.get(), reply -> {
            if (reply.succeeded()) {
                Adapter saved = ((JsonObject) reply.result().body()).getJsonObject(Constant.RESPONSE).mapTo(Adapter.class);
                actual.setId(saved.getId());
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_ADAPTER));
                vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, new JsonObject().put(Constant.ADAPTER, JsonObject.mapFrom(actual)), options.get(), r -> {
                    if (r.succeeded()) {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
                    }
                    else {
                        Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
                    }
                });
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
            }
        });
    }

    public void deleteAdapter(RoutingContext context) {
        String id = context.pathParam("id");
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DELETE_ADAPTER));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.ID, id));
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            if (res.succeeded()) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
            }
            else {
                String uuid = UUID.randomUUID().toString();
                LOGGER.debug(uuid, res.cause());
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 404).put(Constant.ERROR_MESSAGE, "adapter not found").encode());
            }
        });
    }

    private boolean isValid(Adapter adapter) {
        boolean valid = true;

        if (Objects.isNull(adapter.getName()) || adapter.getName().isEmpty()) {
            valid = false;
        }
        if (Objects.isNull(adapter.getDescription()) || adapter.getDescription().isEmpty()) {
            valid = false;
        }
        if (Objects.isNull(adapter.getType())) {
            valid = false;
        }

        if (adapter.getType().equals(AdapterType.OIDC) && (Objects.isNull(adapter.getClientId()) || adapter.getClientId().isEmpty())) {
            valid = false;
        }

        if (adapter.getType().equals(AdapterType.OIDC) && (Objects.isNull(adapter.getPublicKey()) || adapter.getPublicKey().isEmpty())) {
            valid = false;
        }
        return valid;
    }
}
