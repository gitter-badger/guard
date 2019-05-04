package com.demkada.guard.server.users;

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
import com.demkada.guard.server.commons.model.User;
import com.demkada.guard.server.commons.utils.CassandraDriver;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.StringHashUtil;
import com.demkada.guard.server.commons.utils.Utils;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.manager.User_Manager;
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
import java.util.concurrent.atomic.AtomicReference;

public class UserManager extends AbstractVerticle {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserManager.class);
    private User_Manager manager;

    @Override
    public void start(Future<Void> startFuture) {
        manager = ManagerFactoryBuilder_For_Guard
                .builder(CassandraDriver.getOrCreate(config()).getCluster())
                .withDefaultKeyspaceName(Constant.GUARD)
                .doForceSchemaCreation(false)
                .build()
                .forUser();
        vertx.eventBus().consumer(Constant.USER_MANAGER_QUEUE, this::onMessage);
        LOGGER.info("Guard User manager " + this.toString().split("@")[1] + " is up and running");
        startFuture.complete();
    }

    private void onMessage(Message<JsonObject> message) {
        if (!message.headers().contains(Constant.ACTION)) {
            message.fail(ErrorCodes.NO_ACTION_SPECIFIED.ordinal(), "No action header specified");
        }
        String action = message.headers().get(Constant.ACTION);

        switch (action) {
            case Constant.ACTION_INSERT_USER:
                createUser(message);
                break;

            case Constant.ACTION_GET_USERS:
                getUsers(message);
                break;

            case Constant.ACTION_GET_USER_BY_EMAIL:
                getUserByEmail(message);
                break;

            case Constant.ACTION_UPDATE_USER:
                updateUser(message);
                break;

            case Constant.ACTION_CHANGE_USER_STATUS:
                changeUserStatus(message);
                break;

            case Constant.ACTION_CHANGE_EMAIL_STATUS:
                changeEmailStatus(message);
                break;

            case Constant.ACTION_CHANGE_PHONE_STATUS:
                changePhoneStatus(message);
                break;

            case Constant.ACTION_CHANGE_PASS:
                changePassword(message);
                break;

            default:
                message.fail(ErrorCodes.BAD_ACTION.ordinal(), "Bad action: " + action);
        }
    }

    private void createUser(Message<JsonObject> message) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_USER_MODEL_PII));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(message.body().getJsonObject(Constant.USER))));
        vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            if (reply.succeeded()) {
                JsonObject response = (JsonObject) reply.result().body();
                User user = response.getJsonArray(Constant.RESPONSE).getJsonObject(0).mapTo(User.class);
                StringHashUtil.generateHash(vertx, user.getPwd(), ar -> {
                    if (ar.succeeded()) {
                        vertx.executeBlocking(future -> insertUser(user, ar, future), r -> {
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
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), reply.cause().getMessage());
            }
        });
    }

    private void insertUser(User user, AsyncResult<String> ar, Future<Object> future) {
        try {
            user.setPwd(ar.result());
            manager.crud().insert(user).execute();
            future.complete();
        }
        catch (Exception e) {
            future.fail(e);
        }
    }

    private void getUserByEmail(Message<JsonObject> message) {
        String email = message.body().getString(Constant.EMAIL).toLowerCase();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_PRIMARY_KEY));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, email));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            if (res.succeeded()) {
                JsonObject response = (JsonObject) res.result().body();
                vertx.<User>executeBlocking(future -> {
                    try {
                        future.complete(manager.crud().findById(response.getString(Constant.RESPONSE)).get());
                    }
                    catch (Exception e) {
                        future.fail(e);
                    }
                }, r -> handleGetUserByEmailResult(message, r));
            }
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), res.cause().getMessage());
            }
        });
    }

    private void handleGetUserByEmailResult(Message<JsonObject> message, AsyncResult<User> r) {
        if (r.succeeded()) {
            if (Objects.nonNull(r.result())) {
                AtomicReference<DeliveryOptions> options = new AtomicReference<>();
                AtomicReference<JsonObject> entries = new AtomicReference<>();
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_USER_MODEL_PII));
                entries.set(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(JsonObject.mapFrom(r.result()))));
                this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                    if (reply.succeeded()) {
                        JsonObject resp = (JsonObject) reply.result().body();
                        JsonArray array = resp.getJsonArray(Constant.RESPONSE);
                        message.reply(new JsonObject().put(Constant.RESPONSE, array.getJsonObject(0)));
                    }
                    else {
                        message.fail(ErrorCodes.DB_ERROR.ordinal(), reply.cause().getMessage());
                    }
                });
            }
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), "User doesn't exist");
            }
        }
        else {
            message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
        }
    }

    private void getUsers(Message<JsonObject> message) {
        vertx.<List<User>>executeBlocking(future -> {
            try {
                final PreparedStatement statement = manager.getNativeSession().prepare("SELECT email, sub, given_name, family_name, address, email_verified, phone_number, phone_number_verified, disable, guard_id_origin FROM guard.users_by_email");
                future.complete(manager.raw().typedQueryForSelect(statement.bind()).getList());
            }
            catch (Exception e) {
                future.fail(e);
            }
        }, r -> {
            if (r.succeeded()) {
                JsonArray response = new JsonArray();
                r.result().forEach(u -> response.add(JsonObject.mapFrom(Utils.sanitizeUser(u))));
                AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_USER_MODEL_PII));
                AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, response));
                this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                    if (reply.succeeded()) {
                        JsonObject resp = (JsonObject) reply.result().body();
                        JsonArray array = resp.getJsonArray(Constant.RESPONSE);
                        message.reply(new JsonObject().put(Constant.RESPONSE, array));
                    }
                    else {
                        message.fail(ErrorCodes.DB_ERROR.ordinal(), reply.cause().getMessage());
                    }
                });
            }
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

    private void updateUser(Message<JsonObject> message) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_USER_MODEL_PII));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(message.body().getJsonObject(Constant.USER))));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            if (reply.succeeded()) {
                JsonObject response = (JsonObject) reply.result().body();
                User user = response.getJsonArray(Constant.RESPONSE).getJsonObject(0).mapTo(User.class);
                vertx.executeBlocking(future -> {
                    try {
                        manager.crud().update(user).execute();
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
                message.fail(ErrorCodes.DB_ERROR.ordinal(), reply.cause().getMessage());
            }
        });
    }

    private void changeUserStatus(Message<JsonObject> message) {
        String email = message.body().getString(Constant.EMAIL);
        boolean status = message.body().getBoolean(Constant.STATUS);
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_PRIMARY_KEY));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, email));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            if (res.succeeded()) {
                JsonObject response = (JsonObject) res.result().body();
                String cipheredEmail = response.getString(Constant.RESPONSE);
                this.vertx.executeBlocking(future -> {
                    try {
                        manager.dsl()
                                .update()
                                .fromBaseTable()
                                .disable().Set(status)
                                .where()
                                .email().Eq(cipheredEmail)
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
                message.fail(ErrorCodes.DB_ERROR.ordinal(), res.cause().getMessage());
            }
        });
    }

    private void changeEmailStatus(Message<JsonObject> message) {
        String email = message.body().getString(Constant.EMAIL);
        boolean verified = message.body().getBoolean(Constant.STATUS);
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_PRIMARY_KEY));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, email));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            if (res.succeeded()) {
                JsonObject response = (JsonObject) res.result().body();
                String cipheredEmail = response.getString(Constant.RESPONSE);
                this.vertx.executeBlocking(future -> {
                    try {
                        this.manager.dsl()
                                .update()
                                .fromBaseTable()
                                .emailVerified().Set(verified)
                                .where()
                                .email().Eq(cipheredEmail)
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
                message.fail(ErrorCodes.DB_ERROR.ordinal(), res.cause().getMessage());
            }
        });
    }

    private void changePhoneStatus(Message<JsonObject> message) {
        String email = message.body().getString(Constant.EMAIL);
        boolean verified = message.body().getBoolean(Constant.STATUS);
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_PRIMARY_KEY));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, email));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            if (res.succeeded()) {
                JsonObject response = (JsonObject) res.result().body();
                String cipheredEmail = response.getString(Constant.RESPONSE);
                this.vertx.executeBlocking(future -> {
                    try {
                        this.manager.dsl()
                                .update()
                                .fromBaseTable()
                                .phoneNumberVerified().Set(verified)
                                .where()
                                .email().Eq(cipheredEmail)
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
                message.fail(ErrorCodes.DB_ERROR.ordinal(), res.cause().getMessage());
            }
        });
    }

    private void changePassword(Message<JsonObject> message) {
        String email = message.body().getString(Constant.EMAIL);
        String password = message.body().getString(Constant.PASS);
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_PRIMARY_KEY));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, email));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            if (res.succeeded()) {
                JsonObject response = (JsonObject) res.result().body();
                String cipheredEmail = response.getString(Constant.RESPONSE);
                StringHashUtil.generateHash(vertx, password, ar -> {
                    if (ar.succeeded()) {
                        vertx.executeBlocking(future -> {
                            updatePassword(cipheredEmail, ar, future);
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
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), res.cause().getMessage());
            }
        });
    }

    private void updatePassword(String cipheredEmail, AsyncResult<String> ar, Future<Object> future) {
        try {
            manager.dsl()
                    .update()
                    .fromBaseTable()
                    .pwd().Set(ar.result())
                    .where()
                    .email().Eq(cipheredEmail)
                    .ifExists()
                    .execute();
            future.complete();
        }
        catch (Exception e) {
            future.fail(e);
        }
    }

}
