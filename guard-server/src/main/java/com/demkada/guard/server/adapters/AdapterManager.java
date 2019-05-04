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


import com.datastax.driver.core.PreparedStatement;
import com.demkada.guard.server.commons.model.Adapter;
import com.demkada.guard.server.commons.model.ErrorCodes;
import com.demkada.guard.server.commons.utils.CassandraDriver;
import com.demkada.guard.server.commons.utils.Constant;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.manager.Adapter_Manager;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;

public class AdapterManager extends AbstractVerticle {

    private static final Logger LOGGER = LoggerFactory.getLogger(AdapterManager.class);

    private Adapter_Manager manager;

    @Override
    public void start(Future<Void> startFuture) {
        manager = ManagerFactoryBuilder_For_Guard
                .builder(CassandraDriver.getOrCreate(config()).getCluster())
                .withDefaultKeyspaceName(Constant.GUARD)
                .doForceSchemaCreation(false)
                .build()
                .forAdapter();
        vertx.eventBus().consumer(Constant.ADAPTER_MANAGER_QUEUE, this::onMessage);
        LOGGER.info("Guard Adapter manager " + this.toString().split("@")[1] + " is up and running");
        startFuture.complete();
    }

    private void onMessage(Message<JsonObject> message) {
        if (!message.headers().contains(Constant.ACTION)) {
            message.fail(ErrorCodes.NO_ACTION_SPECIFIED.ordinal(), "No action header specified");
        }
        String action = message.headers().get(Constant.ACTION);

        switch (action) {
            case Constant.ACTION_INSERT_ADAPTER:
                createAdapter(message);
                break;

            case Constant.ACTION_GET_ADAPTERS:
                getAdapters(message);
                break;

            case Constant.ACTION_GET_ADAPTER_BY_ID:
                getAdapterById(message);
                break;

            case Constant.ACTION_UPDATE_ADAPTER:
                updateAdapter(message);
                break;

            case Constant.ACTION_DELETE_ADAPTER:
                deleteAdapter(message);
                break;

            default:
                message.fail(ErrorCodes.BAD_ACTION.ordinal(), "Bad action: " + action);
        }
    }

    private void deleteAdapter(Message<JsonObject> message) {
        vertx.<Void>executeBlocking(future -> {
            try {
                String id = message.body().getString(Constant.ID);
                manager.crud().deleteById(id).ifExists().execute();
                future.complete();
            }
            catch (Exception e) {
                future.fail(e);
            }
        }, r -> {
            if (r.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, "done"));
            }
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

    private void updateAdapter(Message<JsonObject> message) {
        vertx.executeBlocking(future -> {
            Adapter adapter = message.body().getJsonObject(Constant.ADAPTER).mapTo(Adapter.class);
            manager.crud().update(adapter).execute();
            future.complete();
        }, r -> {
            if (r.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, "done"));
            }
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

    private void getAdapterById(Message<JsonObject> message) {
        vertx.<Adapter>executeBlocking(future -> {
            try {
                String id = message.body().getString(Constant.ID);
                Adapter adapter = manager.crud().findById(id).get();
                if (Objects.nonNull(adapter)) {
                    future.complete(adapter);
                }
                else {
                    future.fail("not found");
                }
            }
            catch (Exception e) {
                future.fail(e);
            }
        }, r -> {
            if (r.failed()) {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            }
            else {
                message.reply(new JsonObject().put(Constant.RESPONSE, JsonObject.mapFrom(r.result())));
            }
        });
    }

    private void getAdapters(Message<JsonObject> message) {
        vertx.<List<Adapter>>executeBlocking(future -> {
            try {
                final PreparedStatement statement = manager.getNativeSession().prepare("SELECT id, name, description, logo_url, trigger_on_hostname, type, adapter_url, client_id, public_key FROM guard.adapters_by_id");
                future.complete(manager.raw().typedQueryForSelect(statement.bind()).getList());
            }
            catch (Exception e) {
                future.fail(e);
            }
        }, r -> {
            if (r.succeeded()) {
                JsonArray response = new JsonArray();
                r.result().forEach(a -> response.add(JsonObject.mapFrom(a)));
                message.reply(new JsonObject().put(Constant.RESPONSE, response));
            }
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

    private void createAdapter(Message<JsonObject> message) {
        vertx.executeBlocking(future -> {
            try {
                Adapter adapter = message.body().getJsonObject(Constant.ADAPTER).mapTo(Adapter.class);
                manager.crud().insert(adapter).execute();
                future.complete();
            }
            catch (Exception e) {
                future.fail(e);
            }
        }, r -> {
            if (!r.succeeded()) {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            } else {
                message.reply(new JsonObject().put(Constant.RESPONSE, "done"));
            }
        });
    }
}
