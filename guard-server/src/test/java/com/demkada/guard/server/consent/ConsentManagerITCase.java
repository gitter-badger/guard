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
import com.demkada.guard.server.commons.model.Scope;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.Utils;
import com.demkada.guard.server.crypto.CryptoManager;
import com.demkada.guard.server.scope.ScopeManager;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.ManagerFactory_For_Guard;
import info.archinnov.achilles.junit.AchillesTestResource;
import info.archinnov.achilles.junit.AchillesTestResourceBuilder;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

@RunWith(VertxUnitRunner.class)
public class ConsentManagerITCase {

    @Rule
    public AchillesTestResource<ManagerFactory_For_Guard> resource = AchillesTestResourceBuilder
            .forJunit()
            .withScript("guard.cql")
            .truncateBeforeAndAfterTest()
            .tablesToTruncate("users_by_email", "clients_by_id", "scopes_by_name", "consents_by_scope", "authz_code", "refresh_token")
            .build((cluster, statementsCache) -> ManagerFactoryBuilder_For_Guard
                    .builder(cluster)
                    .doForceSchemaCreation(true)
                    .withDefaultKeyspaceName(Constant.GUARD)
                    .build()
            );

    private Vertx vertx;
    private Consent consent1;
    private Consent consent2;
    private Consent consent3;

    @Before
    public void SetUp(TestContext testContext) {

        consent1 = new Consent();
        consent1.setScopeName("scope1");
        consent1.setClientId("client1");
        consent1.setUserEmail("kad@demkada.com");
        consent1.setTimestamp(new Date());

        consent2 = new Consent();
        consent2.setScopeName("scope2");
        consent2.setClientId("client1");
        consent2.setUserEmail("kad@demkada.com");
        consent2.setTimestamp(new Date());

        consent3 = new Consent();
        consent3.setScopeName("scope1");
        consent3.setClientId("client1");
        consent3.setUserEmail("kad.d@demkada.com");
        consent3.setTimestamp(new Date());

        Scope scope1 = new Scope();
        scope1.setName("scope1");
        scope1.setEnDescription("Scope 1 description");

        Scope scope2 = new Scope();
        scope2.setName("scope2");
        scope2.setEnDescription("Scope 2 description");

        resource.getManagerFactory().forScope().crud().insert(scope1).execute();
        resource.getManagerFactory().forScope().crud().insert(scope2).execute();

        vertx = Vertx.vertx();

        io.vertx.core.Future<String> ConsentManagerFuture = io.vertx.core.Future.future();
        vertx.deployVerticle(
                ConsentManager.class.getName(),
                new DeploymentOptions().setConfig(
                        new JsonObject()
                                .put(Constant.CASSANDRA_CLUSTER_CONFIG_KEY, "127.0.0.1")
                                .put(Constant.CASSANDRA_CLUSTER_PORT_KEY, Integer.valueOf(resource.getNativeSession().getCluster().getMetadata().getAllHosts().toArray()[0].toString().split(":")[1]))
                ),
                ar -> {
                    if (ar.succeeded()) {
                        vertx.deployVerticle(
                                ScopeManager.class.getName(),
                                ConsentManagerFuture.completer()
                        );
                    } else {
                        testContext.fail();
                    }
                }
        );

        Future<String> future = Future.future();
        ConsentManagerFuture.compose(v -> vertx.deployVerticle(CryptoManager.class.getName(), future.completer()), future);

        future.setHandler(testContext.asyncAssertSuccess());

    }

    @After
    public void tearDown() {
        vertx.close();
    }

    @Test
    public void shouldInsertConsents(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_CONSENT);
        JsonObject entries = new JsonObject().put(Constant.CONSENT, new JsonArray(Arrays.asList(JsonObject.mapFrom(consent1), JsonObject.mapFrom(consent2))));
        vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            List<Consent> consents = resource.getManagerFactory().forConsent().dsl()
                    .select()
                    .allColumns_FromBaseTable()
                    .where()
                    .scopeName()
                    .IN("scope1", "scope2")
                    .getList();
            testContext.assertNotNull(consents);
            testContext.assertEquals(2, consents.size());
            async.complete();
        });
    }

    @Test
    public void shouldFailWhenInsertingInvalidConsentInBody(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_CONSENT);
        JsonObject entries = new JsonObject().put(Constant.CONSENT, JsonObject.mapFrom(consent1));
        vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertFalse(res.succeeded());
            async.complete();
        });
    }

    @Test
    public void shouldGetAllConsents(TestContext testContext) {
        Async async = testContext.async();
        Utils.encryptpk(vertx, consent1.getUserEmail(), ar -> {
            if (ar.succeeded()) {
                consent1.setUserEmail(ar.result());
                consent2.setUserEmail(ar.result());
                resource.getManagerFactory().forConsent().crud().insert(consent1).execute();
                resource.getManagerFactory().forConsent().crud().insert(consent2).execute();
                Utils.encryptpk(vertx, consent3.getUserEmail(), asyncResult -> {
                    if (asyncResult.succeeded()) {
                        consent3.setUserEmail(asyncResult.result());
                        resource.getManagerFactory().forConsent().crud().insert(consent3).execute();
                        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CONSENTS);
                        JsonObject entries = new JsonObject();
                        vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options, res -> {
                            testContext.assertTrue(res.succeeded());
                            testContext.assertNotNull(res.result().body());
                            List<Consent> consents = new ArrayList<>();
                            JsonObject body = (JsonObject) res.result().body();
                            JsonArray array = body.getJsonArray(Constant.RESPONSE);
                            array.forEach(o -> {
                                JsonObject object = (JsonObject) o;
                                consents.add(object.mapTo(Consent.class));
                            });
                            testContext.assertNotNull(consents);
                            testContext.assertEquals(3, consents.size());
                            async.complete();
                        });
                    } else {
                        testContext.fail();
                    }
                });
            } else {
                testContext.fail();
            }
        });
    }


    @Test
    public void shouldGetEmptyConsentList(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CONSENTS);
        JsonObject entries = new JsonObject();
        vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject body = (JsonObject) res.result().body();
            JsonArray array = body.getJsonArray(Constant.RESPONSE);
            testContext.assertNotNull(array);
            testContext.assertEquals(0, array.size());
            async.complete();
        });
    }


    @Test
    public void shouldGetConsentsByUserForSpecificScopes(TestContext testContext) {
        Async async = testContext.async();
        Utils.encryptpk(vertx, consent1.getUserEmail(), ar -> {
            if (ar.succeeded()) {
                consent1.setUserEmail(ar.result());
                consent2.setUserEmail(ar.result());
                resource.getManagerFactory().forConsent().crud().insert(consent1).execute();
                resource.getManagerFactory().forConsent().crud().insert(consent2).execute();
                Utils.encryptpk(vertx, consent3.getUserEmail(), asyncResult -> {
                    if (asyncResult.succeeded()) {
                        consent3.setUserEmail(asyncResult.result());
                        resource.getManagerFactory().forConsent().crud().insert(consent3).execute();
                        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CONSENTS);
                        JsonObject entries = new JsonObject()
                                .put(Constant.SCOPE_NAME, new JsonArray(Arrays.asList("scope1", "scope2")))
                                .put(Constant.USER_EMAIL, "kad@demkada.com")
                                .put(Constant.CLIENT_ID, consent1.getClientId());
                        vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options, res -> {
                            testContext.assertTrue(res.succeeded());
                            List<Consent> consents = new ArrayList<>();
                            JsonObject body = (JsonObject) res.result().body();
                            JsonArray array = body.getJsonArray(Constant.RESPONSE);
                            array.forEach(o -> {
                                JsonObject object = (JsonObject) o;
                                consents.add(object.mapTo(Consent.class));
                            });
                            testContext.assertNotNull(consents);
                            testContext.assertEquals(2, consents.size());
                            testContext.assertFalse(consents.stream().anyMatch(consent -> "kad.d@demkada.com".equalsIgnoreCase(consent.getUserEmail())));
                            testContext.assertTrue(consents.stream().anyMatch(consent -> "kad@demkada.com".equalsIgnoreCase(consent.getUserEmail())));
                            testContext.assertTrue(consents.stream().anyMatch(consent -> "kad@demkada.com".equalsIgnoreCase(consent.getUserEmail())));
                            async.complete();
                        });
                    } else {
                        testContext.fail();
                    }
                });
            } else {
                testContext.fail();
            }
        });
    }

    @Test
    public void shouldGetAllConsentsByASpecificUser(TestContext testContext) {
        Async async = testContext.async();
        Utils.encryptpk(vertx, consent1.getUserEmail(), ar -> {
            if (ar.succeeded()) {
                consent1.setUserEmail(ar.result());
                consent2.setUserEmail(ar.result());
                resource.getManagerFactory().forConsent().crud().insert(consent1).execute();
                resource.getManagerFactory().forConsent().crud().insert(consent2).execute();
                Utils.encryptpk(vertx, consent3.getUserEmail(), asyncResult -> {
                    if (asyncResult.succeeded()) {
                        consent3.setUserEmail(asyncResult.result());
                        resource.getManagerFactory().forConsent().crud().insert(consent3).execute();
                        JsonObject entries = new JsonObject().put(Constant.USER_EMAIL, "kad@demkada.com");
                        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CONSENTS);
                        vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options, res -> {
                            testContext.assertTrue(res.succeeded());
                            List<Consent> consents = new ArrayList<>();
                            JsonObject body = (JsonObject) res.result().body();
                            JsonArray array = body.getJsonArray(Constant.RESPONSE);
                            array.forEach(o -> {
                                JsonObject object = (JsonObject) o;
                                consents.add(object.mapTo(Consent.class));
                            });
                            testContext.assertNotNull(consents);
                            testContext.assertEquals(2, consents.size());
                            testContext.assertTrue(consents.stream().allMatch(consent -> "kad@demkada.com".equalsIgnoreCase(consent.getUserEmail())));
                            testContext.assertFalse(consents.stream().anyMatch(consent -> "kad.d@demkada.com".equalsIgnoreCase(consent.getUserEmail())));
                            async.complete();
                        });
                    } else {
                        testContext.fail();
                    }
                });
            } else {
                testContext.fail();
            }
        });
    }

    @Test
    public void shouldDeleteConsent(TestContext testContext) {
        Async async = testContext.async();
        Utils.encryptpk(vertx, consent3.getUserEmail(), ar -> {
            if (ar.succeeded()) {
                consent3.setUserEmail(ar.result());
                consent2.setUserEmail(ar.result());
                resource.getManagerFactory().forConsent().crud().insert(consent3).execute();
                resource.getManagerFactory().forConsent().crud().insert(consent2).execute();
                DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DELETE_CONSENT);
                JsonObject entries = new JsonObject()
                        .put(Constant.SCOPE_NAME, consent3.getScopeName())
                        .put(Constant.USER_EMAIL, "kad.d@demkada.com")
                        .put(Constant.CLIENT_ID, consent3.getClientId());
                vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options, res -> {
                    testContext.assertTrue(res.succeeded());
                    Consent updated1 = resource.getManagerFactory().forConsent().crud().findById(consent3.getScopeName(), consent3.getUserEmail(), consent3.getClientId()).get();
                    Consent updated2 = resource.getManagerFactory().forConsent().crud().findById(consent2.getScopeName(), consent2.getUserEmail(), consent2.getClientId()).get();
                    testContext.assertNull(updated1);
                    testContext.assertNotNull(updated2);
                    async.complete();
                });
            } else {
                testContext.fail();
            }
        });
    }

    @Test
    public void shouldNotGoToTimeoutWhenConsentDoesNotExist(TestContext testContext) {
        Async async = testContext.async();
        Utils.encryptpk(vertx, consent3.getUserEmail(), ar -> {
            if (ar.succeeded()) {
                DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DELETE_CONSENT);
                JsonObject entries = new JsonObject()
                        .put(Constant.SCOPE_NAME, "toto")
                        .put(Constant.USER_EMAIL, "kad.d@demkada.com")
                        .put(Constant.CLIENT_ID, consent3.getClientId());
                vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options, res -> {
                    testContext.assertTrue(res.succeeded());
                    async.complete();
                });
            } else {
                testContext.fail();
            }
        });
    }

    @Test
    public void shouldDeleteAllConsentsForASpecificScopeName(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forConsent().crud().insert(consent3).execute();
        resource.getManagerFactory().forConsent().crud().insert(consent2).execute();
        resource.getManagerFactory().forConsent().crud().insert(consent1).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DELETE_CONSENT);
        JsonObject entries = new JsonObject()
                .put(Constant.SCOPE_NAME, consent1.getScopeName());
        vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            PreparedStatement statement = resource.getManagerFactory().forConsent().getNativeSession().prepare("SELECT scope_name, user_email, client_id, timestamp, client_name FROM guard.consents_by_scope");
            List<Consent> result = resource.getManagerFactory().forConsent().raw().typedQueryForSelect(statement.bind()).getList();

            testContext.assertNotNull(result);
            testContext.assertEquals(1, result.size());
            testContext.assertEquals(consent2.getScopeName(), result.get(0).getScopeName());
            async.complete();
        });
    }
}
