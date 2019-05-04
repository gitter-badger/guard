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


import com.demkada.guard.server.Guard;
import com.demkada.guard.server.commons.model.QuestionId;
import com.demkada.guard.server.commons.model.User;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.StringHashUtil;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.ManagerFactory_For_Guard;
import info.archinnov.achilles.junit.AchillesTestResource;
import info.archinnov.achilles.junit.AchillesTestResourceBuilder;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.http.HttpClientOptions;
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

import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(VertxUnitRunner.class)
public class UserRouterITCase {

    static {
        System.setProperty("vertx.disableDnsResolver", "true");
    }

    @Rule
    public AchillesTestResource<ManagerFactory_For_Guard> resource =  AchillesTestResourceBuilder
            .forJunit()
            .withScript("guard.cql")
            .truncateBeforeAndAfterTest()
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
    private int port;

    @Before
    public void SetUp(TestContext testContext) throws IOException {
        user1 = new User();
        user1.setEmail("kad.d@demkada.com");
        user1.setSub("12345");
        user1.setIdOrigin(Constant.GUARD);
        user1.setPwd("toto");
        user1.setAddress("Paris");
        user1.setPhoneNumber("0000");
        user1.setGivenName("Kad");
        user1.setFamilyName("D.");
        Map<QuestionId, String>  secQ = new HashMap<>();
        secQ.put(QuestionId.CHILDHOOD_FRIEND, "Mon meilleur ami d'enfance");
        secQ.put(QuestionId.PRIMARY_SCHOOL, "Tu te souviens bien");
        user1.setSecurityQuestion(secQ);

        user2 = new User();
        user2.setEmail("kadary.dembele@demkada.com");
        user2.setSub("abcde");
        user2.setIdOrigin(Constant.GUARD);
        user2.setPwd("tata");
        user2.setAddress("VDF");
        user2.setPhoneNumber("1111");
        user2.setGivenName("Kadary");
        user2.setFamilyName("DEMBELE");

        ServerSocket serverSocket = new ServerSocket(0);
        port = serverSocket.getLocalPort();
        serverSocket.close();

        vertx = Vertx.vertx();
        vertx.deployVerticle(
                Guard.class.getName(),
                new DeploymentOptions().setConfig(
                        new JsonObject()
                                .put(Constant.GUARD_HTTPS_PORT_CONFIG_KEY, port)
                                .put(Constant.CASSANDRA_CLUSTER_CONFIG_KEY, "127.0.0.1")
                                .put(Constant.CASSANDRA_CLUSTER_PORT_KEY, Integer.valueOf(resource.getNativeSession().getCluster().getMetadata().getAllHosts().toArray()[0].toString().split(":")[1]))
                                .put(Constant.GUARD_CRYPTO_INSTANCES, 1)
                                .put(Constant.GUARD_USERS_INSTANCES, 1)
                                .put(Constant.GUARD_CLIENTS_INSTANCES, 1)
                                .put(Constant.GUARD_SCOPE_INSTANCES, 1)
                                .put(Constant.GUARD_CONSENT_INSTANCES, 1)
                                .put(Constant.GUARD_HTTP_INSTANCES, 1)

                ),
                testContext.asyncAssertSuccess());

    }

    @After
    public void tearDown() {
        vertx.close();
    }

    @Test
    public void shouldGet403WhenTryingToGetUsersWithUserToken(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .get(port, "localhost", "/api/users?email")
                    .handler(resp -> {
                        testContext.assertTrue(403 == resp.statusCode());
                        async.complete();
                    })
                    .putHeader("Content-Type", "application/json")
                 .putHeader("Cookie", "guard=" + token)
                    .end();
        });
    }

    @Test
    public void shouldGet403WhenTryingToGetOtherUserWithUserToken(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forUser().crud().insert(user2).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .get(port, "localhost", "/api/users?email=" + user2.getEmail())
                    .handler(resp -> {
                        testContext.assertTrue(403 == resp.statusCode());
                        async.complete();
                    })
                    .putHeader("Content-Type", "application/json")
                 .putHeader("Cookie", "guard=" + token)
                    .end();
        });
    }

    @Test
    public void shouldGet401WhenTryingToGetUsersDataWithFakeToken(TestContext testContext) {
        Async async = testContext.async();
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/api/users?email=" + user1.getEmail())
                .handler(resp -> {
                    testContext.assertTrue(401 == resp.statusCode());
                    async.complete();
                })
                .putHeader("Content-Type", "application/json")
                .end();
    }

    @Test
    public void shouldUpdateUser(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>();
        AtomicReference<JsonObject> entries = new AtomicReference<>();
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_USER_MODEL_PII));
        entries.set(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(JsonObject.mapFrom(user1))));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            JsonObject object = (JsonObject) reply.result().body();
            User user = object.getJsonArray(Constant.RESPONSE).getJsonObject(0).mapTo(User.class);
            resource.getManagerFactory().forUser().crud().insert(user).execute();
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN));
            entries.set(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 60L));
            user2.setEmail(user1.getEmail());
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                testContext.assertTrue(res.succeeded());
                JsonObject response = (JsonObject) res.result().body();
                String token = response.getString(Constant.RESPONSE);
                vertx.createHttpClient(new HttpClientOptions()
                        .setSsl(true)
                        .setVerifyHost(false)
                        .setTrustAll(true))
                        .put(port, "localhost", "/api/users?email=" + user1.getEmail())
                        .handler(resp -> {
                            testContext.assertTrue(200 == resp.statusCode());
                            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL));
                            entries.set(new JsonObject().put(Constant.EMAIL, "kad.d@demkada.com"));
                            vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), r -> {
                                testContext.assertTrue(r.succeeded());
                                testContext.assertNotNull(r.result().body());
                                JsonObject body = (JsonObject) r.result().body();
                                User updated = body.getJsonObject(Constant.RESPONSE).mapTo(User.class);
                                testContext.assertNotNull(updated);
                                testContext.assertEquals("Kadary", updated.getGivenName());
                                testContext.assertEquals("DEMBELE", updated.getFamilyName());
                                testContext.assertEquals("VDF", updated.getAddress());
                                testContext.assertEquals("1111", updated.getPhoneNumber());
                                testContext.assertEquals("toto", updated.getPwd());
                                async.complete();
                            });

                        })
                        .putHeader("Content-Type", "application/json")
                        .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(user2).toString().length()))
                     .putHeader("Cookie", "guard=" + token)
                        .write(JsonObject.mapFrom(user2).toBuffer())
                        .end();
            });
        });
    }

    @Test
    public void shouldChangePassword(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>();
        AtomicReference<JsonObject> entries = new AtomicReference<>();
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_USER_MODEL_PII));
        entries.set(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(JsonObject.mapFrom(user1))));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            JsonObject object = (JsonObject) reply.result().body();
            User user = object.getJsonArray(Constant.RESPONSE).getJsonObject(0).mapTo(User.class);
            resource.getManagerFactory().forUser().crud().insert(user).execute();
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN));
            entries.set(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 60L));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                testContext.assertTrue(res.succeeded());
                JsonObject response = (JsonObject) res.result().body();
                String token = response.getString(Constant.RESPONSE);
                JsonObject body = new JsonObject().put(Constant.PASS, "newPass");
                vertx.createHttpClient(new HttpClientOptions()
                        .setSsl(true)
                        .setVerifyHost(false)
                        .setTrustAll(true))
                        .put(port, "localhost", "/api/users/password?email=" + user1.getEmail())
                        .handler(resp -> {
                            testContext.assertTrue(200 == resp.statusCode());
                            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL));
                            entries.set(new JsonObject().put(Constant.EMAIL, "kad.d@demkada.com"));
                            vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), r -> {
                                testContext.assertTrue(r.succeeded());
                                testContext.assertNotNull(r.result().body());
                                JsonObject b = (JsonObject) r.result().body();
                                User updated = b.getJsonObject(Constant.RESPONSE).mapTo(User.class);
                                testContext.assertNotNull(updated);
                                StringHashUtil.validatePassword(vertx, "newPass", updated.getPwd(), ar-> {
                                    testContext.assertTrue(ar.result());
                                    async.complete();
                                });
                            });
                        })
                        .putHeader("Content-Type", "application/json")
                        .putHeader("Content-Length", String.valueOf(body.toString().length()))
                     .putHeader("Cookie", "guard=" + token)
                        .write(body.toBuffer())
                        .end();
            });
        });
    }
}