package com.demkada.guard.server.clients;

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
import com.demkada.guard.server.commons.model.Client;
import com.demkada.guard.server.commons.model.ErrorCodes;
import com.demkada.guard.server.commons.utils.CassandraDriver;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.StringHashUtil;
import com.demkada.guard.server.commons.utils.Utils;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.manager.Client_Manager;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;

public class ClientManager extends AbstractVerticle {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientManager.class);

    private Client_Manager manager;

    @Override
    public void start(Future<Void> startFuture) {
        manager = ManagerFactoryBuilder_For_Guard
                .builder(CassandraDriver.getOrCreate(config()).getCluster())
                .withDefaultKeyspaceName(Constant.GUARD)
                .doForceSchemaCreation(false)
                .build()
                .forClient();
        vertx.eventBus().consumer(Constant.CLIENT_MANAGER_QUEUE, this::onMessage);
        LOGGER.info("Guard Clients manager " + this.toString().split("@")[1] + " is up and running");
        startFuture.complete();
    }

    private void onMessage(Message<JsonObject> message) {
        if (!message.headers().contains(Constant.ACTION)) {
            message.fail(ErrorCodes.NO_ACTION_SPECIFIED.ordinal(), "No action header specified");
        }
        String action = message.headers().get(Constant.ACTION);

        switch (action) {
            case Constant.ACTION_INSERT_CLIENT:
                createClient(message);
                break;

            case Constant.ACTION_GET_CLIENTS:
                getClients(message);
                break;

            case Constant.ACTION_GET_CLIENT_BY_ID:
                getClientById(message);
                break;

            case Constant.ACTION_UPDATE_CLIENT:
                updateClient(message);
                break;

            case Constant.ACTION_CHANGE_CLIENT_STATUS:
                changeClientStatus(message);
                break;

            case Constant.ACTION_CHANGE_SECRET:
                changeSecret(message);
                break;

            default:
                message.fail(ErrorCodes.BAD_ACTION.ordinal(), "Bad action: " + action);
        }
    }

    private void createClient(Message<JsonObject> message) {
        Client client = message.body().getJsonObject(Constant.CLIENT).mapTo(Client.class);
        Utils.encryptManagers(vertx, client.getManagers(), ar -> {
            if (ar.succeeded()) {
                client.setManagers(ar.result());
                if (Objects.nonNull(client.getSecret())) {
                    StringHashUtil.generateHash(vertx, client.getSecret(), asyncResult -> {
                        if (asyncResult.succeeded()) {
                            client.setSecret(asyncResult.result());
                            insertClient(message, client);
                        }
                        else {
                            message.fail(ErrorCodes.DB_ERROR.ordinal(), asyncResult.cause().getMessage());
                        }
                    });
                }
                else {
                    insertClient(message, client);
                }
            }
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), ar.cause().getMessage());
            }
        });
    }

    private void insertClient(Message<JsonObject> message, Client client) {
        vertx.executeBlocking(future -> {
            try {
                manager.crud().insert(client).ifNotExists().execute();
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

    private void getClients(Message<JsonObject> message) {
        vertx.<List<Client>>executeBlocking(future -> {
            try {
                final PreparedStatement statement = manager.getNativeSession().prepare("SELECT client_id, client_name, client_type, client_description, client_managers, client_labels, disable FROM guard.clients_by_id");
                future.complete(manager.raw().typedQueryForSelect(statement.bind()).getList());
            }
            catch (Exception e) {
                future.fail(e);
            }
        }, r -> {
            if (r.succeeded()) {
                decryptManagersAndReplyToMessage(message, r);
            }
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            }
        });

    }

    private void decryptManagersAndReplyToMessage(Message<JsonObject> message, AsyncResult<List<Client>> r) {
        JsonArray response = new JsonArray();
        if (r.result().isEmpty()) {
            message.reply(new JsonObject().put(Constant.RESPONSE, response));
        }
        else {
            r.result().forEach(c -> Utils.decryptManagers(vertx, c.getManagers(), ar -> {
                if (ar.succeeded()) {
                    c.setManagers(ar.result());
                    response.add(JsonObject.mapFrom(c));
                    if (response.size() == r.result().size()) {
                        message.reply(new JsonObject().put(Constant.RESPONSE, response));
                    }
                }
                else {
                    message.fail(ErrorCodes.DB_ERROR.ordinal(), ar.cause().getMessage());
                }
            }));
        }
    }

    private void getClientById(Message<JsonObject> message) {
        vertx.<Client>executeBlocking(future -> {
            try {
                String id = message.body().getString(Constant.CLIENT_ID);
                future.complete(manager.crud().findById(id).get());
            }
            catch (Exception e) {
                future.fail(e);
            }
        }, r -> {
            if (r.failed()) {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            }
            else {
                if (Objects.nonNull(r.result())) {
                    Client c = r.result();
                    Utils.decryptManagers(vertx, c.getManagers(), ar -> {
                        if (ar.succeeded()) {
                            c.setManagers(ar.result());
                            message.reply(new JsonObject().put(Constant.RESPONSE, JsonObject.mapFrom(c)));
                        }
                        else {
                            message.fail(ErrorCodes.DB_ERROR.ordinal(), ar.cause().getMessage());
                        }
                    });
                }
                else {
                    message.fail(ErrorCodes.DB_ERROR.ordinal(), "Client doesn't exist");
                }
            }
        });
    }

    private void updateClient(Message<JsonObject> message) {
        vertx.executeBlocking(future -> {
            Client client = message.body().getJsonObject(Constant.CLIENT).mapTo(Client.class);
            Utils.encryptManagers(vertx, client.getManagers(), ar -> {
                if (ar.succeeded()) {
                    client.setManagers(ar.result());
                    try {
                        manager.crud().update(client).execute();
                        future.complete();
                    }
                    catch (Exception e) {
                        future.fail(e);
                    }
                }
                else {
                    message.fail(ErrorCodes.DB_ERROR.ordinal(), ar.cause().getMessage());
                }
            });
        }, r -> {
            if (r.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, "done"));
            }
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

    private void changeClientStatus(Message<JsonObject> message) {
        this.vertx.executeBlocking(future -> {
            String id = message.body().getString(Constant.CLIENT_ID);
            boolean status = message.body().getBoolean(Constant.STATUS);
            try {
                manager.dsl()
                        .update()
                        .fromBaseTable()
                        .disable().Set(status)
                        .where()
                        .id().Eq(id)
                        .ifExists()
                        .execute();
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

    private void changeSecret(Message<JsonObject> message) {
        String secret = message.body().getString(Constant.CLIENT_SECRET);
        StringHashUtil.generateHash(vertx, secret, ar -> {
            if (ar.succeeded()) {
                vertx.executeBlocking(future -> {
                    String id = message.body().getString(Constant.CLIENT_ID);
                    try {
                        manager.dsl()
                                .update()
                                .fromBaseTable()
                                .secret().Set(ar.result())
                                .where()
                                .id().Eq(id)
                                .ifExists()
                                .execute();
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
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), ar.cause().getMessage());
            }
        });
    }

}
