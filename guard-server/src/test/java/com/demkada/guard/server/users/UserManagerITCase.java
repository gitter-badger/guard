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


import com.demkada.guard.server.commons.model.User;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.StringHashUtil;
import com.demkada.guard.server.crypto.CryptoManager;
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
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(VertxUnitRunner.class)
public class UserManagerITCase {

    @Rule
    public AchillesTestResource<ManagerFactory_For_Guard> resource =  AchillesTestResourceBuilder
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
    private User user1;
    private User user2;

    @Before
    public void SetUp(TestContext testContext) {
        user1 = new User();
        user1.setEmail("kad.d@demkada.com");
        user1.setSub("12345");
        user1.setIdOrigin(Constant.GUARD);
        user1.setPwd("toto");
        user1.setAddress("Paris");
        user1.setPhoneNumber("0000");
        user1.setGivenName("Kad");
        user1.setFamilyName("D.");

        user2 = new User();
        user2.setEmail("kadary.dembele@demkada.com");
        user2.setSub("abcde");
        user2.setIdOrigin(Constant.GUARD);
        user2.setPwd("tata");
        user2.setAddress("VDF");
        user2.setPhoneNumber("1111");
        user2.setGivenName("Kadary");
        user2.setFamilyName("DEMBELE");

        vertx = Vertx.vertx();

        io.vertx.core.Future<String> userManagerFuture = io.vertx.core.Future.future();
        vertx.deployVerticle(
                UserManager.class.getName(),
                new DeploymentOptions().setConfig(
                        new JsonObject()
                                .put(Constant.CASSANDRA_CLUSTER_CONFIG_KEY, "127.0.0.1")
                                .put(Constant.CASSANDRA_CLUSTER_PORT_KEY, Integer.valueOf(resource.getNativeSession().getCluster().getMetadata().getAllHosts().toArray()[0].toString().split(":")[1]))
                ),
                userManagerFuture.completer());

        Future<String> future = Future.future();
        userManagerFuture.compose(v -> vertx.deployVerticle(CryptoManager.class.getName(), future.completer()), future);

        future.setHandler(testContext.asyncAssertSuccess());
    }

    @After
    public void tearDown() {
        vertx.close();
    }

    @Test
    public void shouldInsertUser(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_USER));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)));
        vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_PRIMARY_KEY));
            entries.set(new JsonObject().put(Constant.PAYLOAD, user1.getEmail()));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                JsonObject response = (JsonObject) reply.result().body();
                User u = resource.getManagerFactory().forUser().crud().findById(response.getString(Constant.RESPONSE)).get();
                testContext.assertNotNull(u);
                testContext.assertNotEquals("Kad", u.getGivenName());
                testContext.assertNotEquals("toto", u.getPwd());
                StringHashUtil.validatePassword(vertx,"toto", u.getPwd(), r -> {
                    testContext.assertTrue(r.result());
                    async.complete();
                });
            });
        });
    }

    @Test
    public void shouldGetUserByEmail(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>();
        AtomicReference<JsonObject> entries = new AtomicReference<>();
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_USER_MODEL_PII));
        entries.set(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(JsonObject.mapFrom(user1))));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            JsonObject response = (JsonObject) reply.result().body();
            User user = response.getJsonArray(Constant.RESPONSE).getJsonObject(0).mapTo(User.class);
            resource.getManagerFactory().forUser().crud().insert(user).execute();
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL));
            entries.set(new JsonObject().put(Constant.EMAIL, "kad.d@demkada.com"));
            vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                testContext.assertTrue(res.succeeded());
                testContext.assertNotNull(res.result().body());
                JsonObject body = (JsonObject) res.result().body();
                User u = body.getJsonObject(Constant.RESPONSE).mapTo(User.class);
                testContext.assertNotNull(u);
                testContext.assertEquals("Kad", u.getGivenName());
                testContext.assertEquals("Paris", u.getAddress());
                testContext.assertEquals(user1.getSub(), u.getSub());
                async.complete();
            });
        });
    }

    @Test
    public void shouldGetUsers(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>();
        AtomicReference<JsonObject> entries = new AtomicReference<>();
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_USER_MODEL_PII));
        entries.set(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(JsonObject.mapFrom(user1)).add(JsonObject.mapFrom(user2))));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            JsonObject response = (JsonObject) reply.result().body();
            response.getJsonArray(Constant.RESPONSE).forEach(o -> resource.getManagerFactory().forUser().crud().insert(((JsonObject) o).mapTo(User.class)).execute());
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USERS));
            entries.set(new JsonObject());
            vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                testContext.assertTrue(res.succeeded());
                testContext.assertNotNull(res.result().body());
                List<User> u = new ArrayList<>();
                JsonObject body = (JsonObject) res.result().body();
                JsonArray array = body.getJsonArray(Constant.RESPONSE);
                array.forEach(o -> {
                    JsonObject object = (JsonObject) o;
                    u.add(object.mapTo(User.class));
                });
                testContext.assertNotNull(u);
                testContext.assertEquals(2, u.size());
                testContext.assertTrue(u.stream().anyMatch(user -> "kadary.dembele@demkada.com".equalsIgnoreCase(user.getEmail())));
                testContext.assertTrue(u.stream().anyMatch(user -> "kad.d@demkada.com".equalsIgnoreCase(user.getEmail())));
                async.complete();
            });
        });
    }

    @Test
    public void shouldUpdateUser(TestContext testContext) {
        Async async = testContext.async();
        user1.setPhoneNumberVerified(true);
        AtomicReference<DeliveryOptions> options = new AtomicReference<>();
        AtomicReference<JsonObject> entries = new AtomicReference<>();
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_USER_MODEL_PII));
        entries.set(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(JsonObject.mapFrom(user1))));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            JsonObject response = (JsonObject) reply.result().body();
            User user = response.getJsonArray(Constant.RESPONSE).getJsonObject(0).mapTo(User.class);
            resource.getManagerFactory().forUser().crud().insert(user).execute();
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL));
            entries.set(new JsonObject().put(Constant.EMAIL, "kad.d@demkada.com"));
            vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                testContext.assertTrue(res.succeeded());
                testContext.assertNotNull(res.result().body());
                JsonObject body = (JsonObject) res.result().body();
                User u = body.getJsonObject(Constant.RESPONSE).mapTo(User.class);
                testContext.assertNotNull(u);
                testContext.assertEquals("Kad", u.getGivenName());
                testContext.assertEquals("D.", u.getFamilyName());
                testContext.assertEquals("Paris", u.getAddress());
                testContext.assertEquals("0000", u.getPhoneNumber());
                testContext.assertTrue(u.isPhoneNumberVerified());
                testContext.assertEquals("toto", u.getPwd());

                user2.setEmail(user1.getEmail());
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_USER));
                entries.set(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user2)));
                vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), asyncResult -> {
                    testContext.assertTrue(asyncResult.succeeded());
                    testContext.assertNotNull(asyncResult.result().body());
                    options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL));
                    entries.set(new JsonObject().put(Constant.EMAIL, "kad.d@demkada.com"));
                    vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), res1 -> {
                        JsonObject b = (JsonObject) res1.result().body();
                        User updated = b.getJsonObject(Constant.RESPONSE).mapTo(User.class);
                        testContext.assertNotNull(updated);
                        testContext.assertEquals("Kadary", updated.getGivenName());
                        testContext.assertEquals("DEMBELE", updated.getFamilyName());
                        testContext.assertEquals("VDF", updated.getAddress());
                        testContext.assertEquals("1111", updated.getPhoneNumber());
                        testContext.assertFalse(updated.isPhoneNumberVerified());
                        testContext.assertEquals("tata", updated.getPwd());
                        async.complete();
                            });
                });
            });
        });
    }

    @Test
    public void shouldChangeUserStatus(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>();
        AtomicReference<JsonObject> entries = new AtomicReference<>();
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_USER_MODEL_PII));
        entries.set(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(JsonObject.mapFrom(user1))));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            JsonObject response = (JsonObject) reply.result().body();
            User user = response.getJsonArray(Constant.RESPONSE).getJsonObject(0).mapTo(User.class);
            resource.getManagerFactory().forUser().crud().insert(user).execute();
            User u = resource.getManagerFactory().forUser().crud().findById(user.getEmail()).get();
            testContext.assertFalse(u.isDisable());
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_USER_STATUS));
            entries.set(new JsonObject().put(Constant.EMAIL, "kad.d@demkada.com")
                    .put(Constant.STATUS, true));
            vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                testContext.assertTrue(res.succeeded());
                testContext.assertNotNull(res.result().body());
                User updated = resource.getManagerFactory().forUser().crud().findById(user.getEmail()).get();
                testContext.assertNotNull(updated);
                testContext.assertTrue(updated.isDisable());
                async.complete();
            });
        });
    }

    @Test
    public void shouldChangeEmailStatus(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>();
        AtomicReference<JsonObject> entries = new AtomicReference<>();
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_USER_MODEL_PII));
        entries.set(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(JsonObject.mapFrom(user1))));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            JsonObject response = (JsonObject) reply.result().body();
            User user = response.getJsonArray(Constant.RESPONSE).getJsonObject(0).mapTo(User.class);
            resource.getManagerFactory().forUser().crud().insert(user).execute();
            User u = resource.getManagerFactory().forUser().crud().findById(user.getEmail()).get();
            testContext.assertFalse(u.isEmailVerified());
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_EMAIL_STATUS));
            entries.set(new JsonObject().put(Constant.EMAIL, "kad.d@demkada.com")
                    .put(Constant.STATUS, true));
            vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                testContext.assertTrue(res.succeeded());
                testContext.assertNotNull(res.result().body());
                User updated = resource.getManagerFactory().forUser().crud().findById(user.getEmail()).get();
                testContext.assertNotNull(updated);
                testContext.assertTrue(updated.isEmailVerified());
                async.complete();
            });
        });
    }

    @Test
    public void shouldChangePhoneStatus(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>();
        AtomicReference<JsonObject> entries = new AtomicReference<>();
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_USER_MODEL_PII));
        entries.set(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(JsonObject.mapFrom(user1))));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            JsonObject response = (JsonObject) reply.result().body();
            User user = response.getJsonArray(Constant.RESPONSE).getJsonObject(0).mapTo(User.class);
            resource.getManagerFactory().forUser().crud().insert(user).execute();
            User u = resource.getManagerFactory().forUser().crud().findById(user.getEmail()).get();
            testContext.assertFalse(u.isPhoneNumberVerified());
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_PHONE_STATUS));
            entries.set(new JsonObject().put(Constant.EMAIL, "kad.d@demkada.com")
                    .put(Constant.STATUS, true));
            vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                testContext.assertTrue(res.succeeded());
                testContext.assertNotNull(res.result().body());
                User updated = resource.getManagerFactory().forUser().crud().findById(user.getEmail()).get();
                testContext.assertNotNull(updated);
                testContext.assertTrue(updated.isPhoneNumberVerified());
                async.complete();
            });
        });
    }

    @Test
    public void shouldChangePassword(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_USER));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)));
        vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_PRIMARY_KEY));
            entries.set(new JsonObject().put(Constant.PAYLOAD, user1.getEmail()));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                testContext.assertTrue(reply.succeeded());
                testContext.assertNotNull(reply.result().body());
                JsonObject response = (JsonObject) reply.result().body();
                User u = resource.getManagerFactory().forUser().crud().findById(response.getString(Constant.RESPONSE)).get();
                StringHashUtil.validatePassword(vertx, "toto", u.getPwd(), r -> {
                    testContext.assertTrue(r.result());
                    options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_PASS));
                    entries.set(new JsonObject().put(Constant.EMAIL, "kad.d@demkada.com")
                            .put(Constant.PASS, "tata"));
                    vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), asyncResult -> {
                        testContext.assertTrue(asyncResult.succeeded());
                        testContext.assertNotNull(asyncResult.result().body());
                        User updated = resource.getManagerFactory().forUser().crud().findById(response.getString(Constant.RESPONSE)).get();
                        StringHashUtil.validatePassword(vertx, "toto", updated.getPwd(), p -> {
                            testContext.assertFalse(p.result());
                            StringHashUtil.validatePassword(vertx, "tata", updated.getPwd(), p1 -> {
                                testContext.assertTrue(p1.result());
                                async.complete();
                            });
                        });
                    });
                });
            });
        });
    }

}