package com.demkada.guard.server.consent;

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
import com.demkada.guard.server.commons.model.Consent;
import com.demkada.guard.server.commons.model.ConsentByUserMV;
import com.demkada.guard.server.commons.model.ErrorCodes;
import com.demkada.guard.server.commons.model.Scope;
import com.demkada.guard.server.commons.utils.CassandraDriver;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.Utils;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.manager.ConsentByUserMV_Manager;
import info.archinnov.achilles.generated.manager.Consent_Manager;
import io.vertx.core.*;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class ConsentManager extends AbstractVerticle {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConsentManager.class);


    private Consent_Manager consentMgr;
    private ConsentByUserMV_Manager consentByUserMVManager;

    @Override
    public void start(Future<Void> startFuture) {

        consentMgr = ManagerFactoryBuilder_For_Guard
                .builder(CassandraDriver.getOrCreate(config()).getCluster())
                .withDefaultKeyspaceName(Constant.GUARD)
                .doForceSchemaCreation(false)
                .build()
                .forConsent();
        consentByUserMVManager = ManagerFactoryBuilder_For_Guard
                .builder(CassandraDriver.getOrCreate(config()).getCluster())
                .withDefaultKeyspaceName(Constant.GUARD)
                .doForceSchemaCreation(false)
                .build()
                .forConsentByUserMV();

        vertx.eventBus().consumer(Constant.CONSENT_MANAGER_QUEUE, this::onMessage);
        LOGGER.info("Guard Consent manager " + this.toString().split("@")[1] + " is up and running");
        startFuture.complete();
    }

    private void onMessage(Message<JsonObject> message) {
        if (!message.headers().contains(Constant.ACTION)) {
            message.fail(ErrorCodes.NO_ACTION_SPECIFIED.ordinal(), "No action header specified");
        }
        String action = message.headers().get(Constant.ACTION);

        switch (action) {
            case Constant.ACTION_INSERT_CONSENT:
                createConsent(message);
                break;

            case Constant.ACTION_GET_CONSENTS:
                getConsents(message);
                break;

            case Constant.ACTION_DELETE_CONSENT:
                deleteConsent(message);
                break;

            default:
                message.fail(ErrorCodes.BAD_ACTION.ordinal(), "Bad action: " + action);
        }

    }

    private void createConsent(Message<JsonObject> message) {
        vertx.executeBlocking(future -> {
            try {
                List<Future> futureList = new ArrayList<>();
                JsonArray input = message.body().getJsonArray(Constant.CONSENT);
                input.forEach(c -> {
                    Future<Void> f = Future.future();
                    JsonObject o = (JsonObject) c;
                    Consent consent = o.mapTo(Consent.class);
                    consent.setTimestamp(new Date());
                    insertConsent(consent, f);
                    futureList.add(f);
                });
                CompositeFuture.all(futureList).setHandler(ar -> {
                  if (ar.succeeded()) {
                      future.complete();
                  }
                  else {
                      future.fail(ar.cause());
                  }
                });
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

    private void insertConsent(Consent consent, Handler<AsyncResult<Void>> handler) {
        Future<Void> f = Future.future();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPES);
        JsonObject entries = new JsonObject().put(Constant.SCOPE_NAME, new JsonArray().add(consent.getScopeName()));
        AtomicLong seconds = new AtomicLong(0);
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries, options, res -> {
            if (res.succeeded()) {
                JsonArray response = ((JsonObject) res.result().body()).getJsonArray(Constant.RESPONSE);
                if (!response.isEmpty()) {
                    JsonObject s = response.getJsonObject(0);
                    if (Objects.nonNull(s)) {
                        Scope scope = s.mapTo(Scope.class);
                        seconds.set(TimeUnit.SECONDS.convert(scope.getConsentTTL(), TimeUnit.DAYS));
                    }
                    if (seconds.get() > 0)  {
                        consent.setExpire(Date.from(Instant.now().plusSeconds(seconds.get())));
                    }
                    else {
                        consent.setExpire(Date.from(Instant.now().plusSeconds(TimeUnit.SECONDS.convert(Constant.DEFAULT_CONSENT_TTL, TimeUnit.DAYS))));
                    }
                }
                else {
                    f.fail("Scope does not exist");
                }
            }
            else {
                f.fail(res.cause());
            }
            Utils.encryptpk(vertx, consent.getUserEmail(), ar -> {
                if (ar.succeeded()) {
                    consent.setUserEmail(ar.result());
                    consentMgr.crud().insert(consent).usingTimeToLive((int) seconds.get()).execute();
                    f.complete();
                }
                else {
                    f.fail(ar.cause());
                }
            });
        });
        f.setHandler(handler);
    }

    private void getConsents(Message<JsonObject> message) {
        JsonArray scopes = message.body().getJsonArray(Constant.SCOPE_NAME);
        String userEmail = message.body().getString(Constant.USER_EMAIL);
        String clientId = message.body().getString(Constant.CLIENT_ID);
        vertx.<JsonArray>executeBlocking(future -> processGetConsentsRequest(message, scopes, userEmail, clientId, future), r -> {
            if (r.succeeded()) {
                if (r.result().isEmpty()) {
                    message.reply(new JsonObject().put(Constant.RESPONSE, new JsonArray()));
                }
                else {
                    decryptPkAndReplyToEvent(message, r);
                }
            }
            else {
                message.fail(ErrorCodes.DB_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

    private void decryptPkAndReplyToEvent(Message<JsonObject> message, AsyncResult<JsonArray> r) {
        JsonArray response = new JsonArray();
        if (r.result().isEmpty()) {
            message.reply(new JsonObject().put(Constant.RESPONSE, response));
        }
        else {
            r.result().forEach(c -> {
                Consent consent = ((JsonObject) c).mapTo(Consent.class);
                Utils.decryptPk(vertx, consent.getUserEmail(), ar -> {
                    if (ar.succeeded()) {
                        consent.setUserEmail(ar.result());
                        response.add(JsonObject.mapFrom(consent));
                        if (response.size() == r.result().size()) {
                            message.reply(new JsonObject().put(Constant.RESPONSE, response));
                        }
                    }
                    else {
                        message.fail(ErrorCodes.DB_ERROR.ordinal(), ar.cause().getMessage());
                    }
                });
            });
        }
    }

    private void processGetConsentsRequest(Message<JsonObject> message, JsonArray scopes, String userEmail, String clientId, Future<JsonArray> future) {
        try {
            AtomicReference<List<Consent>> result = new AtomicReference<>();
            if (Objects.nonNull(scopes) && !scopes.isEmpty() && Objects.nonNull(userEmail) && Objects.nonNull(clientId)) {
                Utils.encryptpk(vertx, userEmail, ar -> {
                    if (ar.succeeded()) {
                        List<String> scopeName = new ArrayList<>();
                        scopes.forEach(s -> scopeName.add((String) s));
                        result.set(consentMgr
                                .dsl()
                                .select()
                                .allColumns_FromBaseTable()
                                .where()
                                .scopeName().IN(scopeName.toArray(new String[scopeName.size()]))
                                .userEmail().Eq(ar.result())
                                .clientId().Eq(clientId)
                                .getList());
                        JsonArray response = new JsonArray();
                        result.get().forEach(c -> response.add(JsonObject.mapFrom(c)));
                        future.complete(response);
                    }
                    else {
                        message.fail(ErrorCodes.DB_ERROR.ordinal(), ar.cause().getMessage());
                    }
                });
            }
            else if (Objects.nonNull(userEmail)) {
                getConsentsByUser(message);
            }
            else {
                PreparedStatement statement = consentMgr.getNativeSession().prepare("SELECT scope_name, user_email, client_id, timestamp, expire_at, client_name FROM guard.consents_by_scope");
                result.set(consentMgr.raw().typedQueryForSelect(statement.bind()).getList());
                JsonArray response = new JsonArray();
                result.get().forEach(c -> response.add(JsonObject.mapFrom(c)));
                future.complete(response);
            }
        }
        catch (Exception e) {
            future.fail(e);
        }
    }

    private void getConsentsByUser(Message<JsonObject> message) {
        String userEmail = message.body().getString(Constant.USER_EMAIL);
        Utils.encryptpk(vertx, userEmail, ar -> {
            if (ar.succeeded()) {
                vertx.<JsonArray>executeBlocking(future -> {
                    try {
                        List<ConsentByUserMV> result = consentByUserMVManager
                                .dsl()
                                .select()
                                .allColumns_FromBaseTable()
                                .where()
                                .userEmail().Eq(ar.result())
                                .getList();
                        JsonArray response = new JsonArray();
                        result.forEach(c -> response.add(JsonObject.mapFrom(c)));
                        future.complete(response);
                    }
                    catch (Exception e) {
                        future.fail(e);
                    }
                }, r -> {
                    if (r.succeeded()) {
                        decryptPkAndReplyToEvent(message, r);
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

    private void deleteConsent(Message<JsonObject> message) {
        String scopeName = message.body().getString(Constant.SCOPE_NAME);
        String userEmail = message.body().getString(Constant.USER_EMAIL);
        String clientId = message.body().getString(Constant.CLIENT_ID);
        vertx.<Void>executeBlocking(future -> {
            try {
                if (Objects.nonNull(scopeName) && Objects.nonNull(userEmail) && Objects.nonNull(clientId)) {
                    Utils.encryptpk(vertx, userEmail, ar -> {
                        if (ar.succeeded()) {
                            consentMgr
                                    .dsl()
                                    .delete()
                                    .allColumns_FromBaseTable()
                                    .where()
                                    .scopeName().Eq(scopeName)
                                    .userEmail().Eq(ar.result())
                                    .clientId().Eq(clientId)
                                    .execute();
                            future.complete();
                        }
                        else {
                            message.fail(ErrorCodes.DB_ERROR.ordinal(), ar.cause().getMessage());
                        }
                    });
                }
                else if (Objects.nonNull(scopeName)) {
                    consentMgr.crud().deleteByPartitionKeys(scopeName).execute();
                    future.complete();
                }
                else {
                    future.fail("invalid input");
                }
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
}
