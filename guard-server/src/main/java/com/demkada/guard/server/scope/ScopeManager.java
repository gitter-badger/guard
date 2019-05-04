package com.demkada.guard.server.scope;

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
import com.demkada.guard.server.commons.model.ErrorCodes;
import com.demkada.guard.server.commons.model.Scope;
import com.demkada.guard.server.commons.utils.CassandraDriver;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.Utils;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.manager.Scope_Manager;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;

public class ScopeManager extends AbstractVerticle {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScopeManager.class);

    private Scope_Manager manager;

    @Override
    public void start(Future<Void> startFuture) {
        manager = ManagerFactoryBuilder_For_Guard
                .builder(CassandraDriver.getOrCreate(config()).getCluster())
                .withDefaultKeyspaceName(Constant.GUARD)
                .doForceSchemaCreation(false)
                .build()
                .forScope();
        vertx.eventBus().consumer(Constant.SCOPE_MANAGER_QUEUE, this::onMessage);
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(String.format("Guard Scope manager %s is up and running", this.toString().split("@")[1]));
        }
        startFuture.complete();
    }

    private void onMessage(Message<JsonObject> message) {
        if (!message.headers().contains(Constant.ACTION)) {
            message.fail(ErrorCodes.NO_ACTION_SPECIFIED.ordinal(), "No action header specified");
        }
        String action = message.headers().get(Constant.ACTION);

        switch (action) {
            case Constant.ACTION_INSERT_SCOPE:
                createScope(message);
                break;

            case Constant.ACTION_GET_SCOPES:
                getScopes(message);
                break;

            case Constant.ACTION_GET_SCOPE_BY_NAME:
                getScopeByName(message);
                break;

            case Constant.ACTION_UPDATE_SCOPE:
                updateScope(message);
                break;


            case Constant.ACTION_DELETE_SCOPE:
                deleteScope(message);
                break;

            default:
                message.fail(ErrorCodes.BAD_ACTION.ordinal(), "Bad action: " + action);
        }
    }

    private void createScope(Message<JsonObject> message) {
        Scope scope = message.body().getJsonObject(Constant.SCOPE).mapTo(Scope.class);
        Utils.encryptManagers(vertx, scope.getManagers(), ar -> {
            if (ar.succeeded()) {
                scope.setManagers(ar.result());
                vertx.executeBlocking(future -> {
                    try {
                        manager.crud().insert(scope).execute();
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

    private void getScopes(Message<JsonObject> message) {
        JsonArray scopes = message.body().getJsonArray(Constant.SCOPE_NAME);
        vertx.<List<Scope>>executeBlocking(future -> {
            try {
                PreparedStatement statement;
                if (Objects.nonNull(scopes) && !scopes.isEmpty()) {
                    statement = manager.getNativeSession().prepare("SELECT name, en_description, fr_description, scope_managers, restricted, one_shot, end_user_mfa, machine_mfa, client_id_list, client_id_list_for_implicit_consent, refresh_token_ttl, consent_ttl, consent_url, trust_ca_chain, authorized_flows FROM guard.scopes_by_name WHERE name IN ?;");
                    future.complete(manager.raw().typedQueryForSelect(statement.bind(scopes.getList())).getList());
                }
                else {
                    statement = manager.getNativeSession().prepare("SELECT name, en_description, fr_description, scope_managers, restricted, one_shot, end_user_mfa, machine_mfa, client_id_list, client_id_list_for_implicit_consent, refresh_token_ttl, consent_ttl, consent_url, trust_ca_chain, authorized_flows FROM guard.scopes_by_name;");
                    future.complete(manager.raw().typedQueryForSelect(statement.bind()).getList());
                }
            }
            catch (Exception e) {
                future.fail(e);
            }
        }, r -> {
            if (!r.succeeded()) {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            } else {
                decryptManagersAndReplyToMessage(message, r);
            }
        });
    }

    private void decryptManagersAndReplyToMessage(Message<JsonObject> message, AsyncResult<List<Scope>> r) {
        JsonArray response = new JsonArray();
        if (r.result().isEmpty()) {
            message.reply(new JsonObject().put(Constant.RESPONSE, response));
        }
        else {
            r.result().forEach(s -> Utils.decryptManagers(vertx, s.getManagers(), ar -> {
                if (ar.failed()) {
                    message.fail(ErrorCodes.DB_ERROR.ordinal(), ar.cause().getMessage());
                }
                else {
                    s.setManagers(ar.result());
                    response.add(JsonObject.mapFrom(s));
                    if (response.size() == r.result().size()) {
                        message.reply(new JsonObject().put(Constant.RESPONSE, response));
                    }
                }
            }));
        }
    }

    private void getScopeByName(Message<JsonObject> message) {
        String name = message.body().getString(Constant.SCOPE_NAME);
        vertx.<Scope>executeBlocking(future -> {
            try {
                future.complete(manager.crud().findById(name).get());
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
                    Scope s = r.result();
                    Utils.decryptManagers(vertx, s.getManagers(), ar -> {
                        if (ar.failed()) {
                            message.fail(ErrorCodes.DB_ERROR.ordinal(), ar.cause().getMessage());
                        }
                        else {
                            s.setManagers(ar.result());
                            message.reply(new JsonObject().put(Constant.RESPONSE, JsonObject.mapFrom(s)));
                        }
                    });
                }
                else {
                    message.fail(ErrorCodes.DB_ERROR.ordinal(), "Scope doesn't exist");
                }
            }
        });

    }

    private void updateScope(Message<JsonObject> message) {
        vertx.executeBlocking(future -> {
            Scope scope = message.body().getJsonObject(Constant.SCOPE).mapTo(Scope.class);
            Utils.encryptManagers(vertx, scope.getManagers(), ar -> {
                if (ar.failed()) {
                    message.fail(ErrorCodes.DB_ERROR.ordinal(), ar.cause().getMessage());
                }
                else {
                    scope.setManagers(ar.result());
                    try {
                        manager.crud().update(scope).execute();
                        future.complete();
                    }
                    catch (Exception e) {
                        future.fail(e);
                    }
                }
            });
        }, r -> {
            if (!r.succeeded()) {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            } else {
                message.reply(new JsonObject().put(Constant.RESPONSE, "done"));
            }
        });

    }

    private void deleteScope(Message<JsonObject> message) {
        String name = message.body().getString(Constant.SCOPE_NAME);
        vertx.<Void>executeBlocking(future -> {
            try {
                manager.crud().deleteById(name).ifExists().execute();
                future.complete();
            }
            catch (Exception e) {
                future.fail(e);
            }
        }, r -> {
            if (r.succeeded()) {
                DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DELETE_CONSENT);
                JsonObject event = new JsonObject().put(Constant.SCOPE_NAME, name);
                vertx.eventBus().publish(Constant.CONSENT_MANAGER_QUEUE, event, options);
                message.reply(new JsonObject().put(Constant.RESPONSE, "done"));
            }
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

}
