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


import com.demkada.guard.server.Guard;
import com.demkada.guard.server.commons.model.Adapter;
import com.demkada.guard.server.commons.model.AdapterType;
import com.demkada.guard.server.commons.model.QuestionId;
import com.demkada.guard.server.commons.model.User;
import com.demkada.guard.server.commons.utils.Constant;
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

@RunWith(VertxUnitRunner.class)
public class AdapterRouterITCase {

    static {
        System.setProperty("vertx.disableDnsResolver", "true");
    }

    @Rule
    public AchillesTestResource<ManagerFactory_For_Guard> resource = AchillesTestResourceBuilder
            .forJunit()
            .withScript("guard.cql")
            .truncateBeforeAndAfterTest()
            .tablesToTruncate("adapters_by_id", "users_by_email", "clients_by_id", "scopes_by_name", "consents_by_scope", "authz_code", "refresh_token")
            .build((cluster, statementsCache) -> ManagerFactoryBuilder_For_Guard
                    .builder(cluster)
                    .doForceSchemaCreation(true)
                    .withDefaultKeyspaceName(Constant.GUARD)
                    .build()
            );

    private Vertx vertx;
    private User user;
    private Adapter adapter1;
    private Adapter adapter2;
    private int port;

    @Before
    public void SetUp(TestContext testContext) throws IOException {

        user = new User();
        user.setEmail("kad.d@demkada.com");
        user.setSub("12345");
        user.setIdOrigin(Constant.GUARD);
        user.setPwd("toto");
        user.setAddress("Paris");
        user.setPhoneNumber("0000");
        user.setGivenName("Kad");
        user.setFamilyName("D.");
        Map<QuestionId, String> secQ = new HashMap<>();
        secQ.put(QuestionId.CHILDHOOD_FRIEND, "Mon meilleur ami d'enfance");
        secQ.put(QuestionId.PRIMARY_SCHOOL, "Tu te souviens bien");
        user.setSecurityQuestion(secQ);

        adapter1 = new Adapter();
        adapter1.setId("12345");
        adapter1.setName("SAS");
        adapter1.setType(AdapterType.OIDC);
        adapter1.setDescription("SAS OIDC adapter");
        adapter1.setClientId("xyz");
        adapter1.setPublicKey("key");
        adapter1.setAdapterUrl("https://sas.com");
        adapter1.setLogoUrl("https://sas.com/logo.png");

        adapter2 = new Adapter();
        adapter2.setId("ABCDE");
        adapter2.setName("SAFE");
        adapter2.setType(AdapterType.NATIVE);
        adapter2.setDescription("SAFE Native adapter");
        adapter2.setAdapterUrl("https://safe.com");
        adapter2.setLogoUrl("https://safe.com/logo.png");

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
                                .put(Constant.GUARD_SERVER_ADMIN, new JsonArray().add(user.getEmail()))
                                .put(Constant.GUARD_CRYPTO_INSTANCES, 1)
                                .put(Constant.GUARD_USERS_INSTANCES, 1)
                                .put(Constant.GUARD_CLIENTS_INSTANCES, 1)
                                .put(Constant.GUARD_SCOPE_INSTANCES, 1)
                                .put(Constant.GUARD_CONSENT_INSTANCES, 1)
                                .put(Constant.GUARD_HTTP_INSTANCES, 1)

                ), testContext.asyncAssertSuccess());
    }

    @After
    public void tearDown() {
        vertx.close();
    }

    @Test
    public void shouldRejectRequestWhenUserIsNotAdmin(TestContext testContext) {
        Async async = testContext.async();
        user.setEmail("k.d@demkada.com");
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .post(port, "localhost", "/api/adapters")
                    .handler(resp -> {
                        testContext.assertTrue(403 == resp.statusCode());
                        async.complete();
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(adapter1).toString().length()))
                    .putHeader("Cookie", "guard=" + ((JsonObject) res.result().body()).getString(Constant.RESPONSE))
                    .write(JsonObject.mapFrom(adapter1).toBuffer())
                    .end();
        });
    }

    @Test
    public void shouldCreateAdapter(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .post(port, "localhost", "/api/adapters")
                    .handler(resp -> {
                        testContext.assertTrue(201 == resp.statusCode());
                        resp.bodyHandler(b -> {
                            testContext.assertNotNull(b.toJsonObject());
                            testContext.assertNotNull(b.toJsonObject().getString("id"));
                            async.complete();
                        });
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(adapter1).toString().length()))
                    .putHeader("Cookie", "guard=" + ((JsonObject) res.result().body()).getString(Constant.RESPONSE))
                    .write(JsonObject.mapFrom(adapter1).toBuffer())
                    .end();
        });
    }

    @Test
    public void shouldGetAdapters(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forAdapter().crud().insert(adapter1).execute();
        resource.getManagerFactory().forAdapter().crud().insert(adapter2).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .get(port, "localhost", "/api/adapters")
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        resp.bodyHandler(b -> {
                            testContext.assertNotNull(b.toJsonArray());
                            testContext.assertEquals(2, b.toJsonArray().size());
                            async.complete();
                        });
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Cookie", "guard=" + ((JsonObject) res.result().body()).getString(Constant.RESPONSE))
                    .end();
        });
    }

    @Test
    public void shouldGetAdapterById(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forAdapter().crud().insert(adapter1).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .get(port, "localhost", "/api/adapters/" + adapter1.getId())
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        resp.bodyHandler(b -> {
                            testContext.assertNotNull(b.toJsonObject());
                            testContext.assertEquals(adapter1.getName(), b.toJsonObject().getString("name"));
                            testContext.assertEquals(adapter1.getId(), b.toJsonObject().getString("id"));
                            async.complete();
                        });
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Cookie", "guard=" + ((JsonObject) res.result().body()).getString(Constant.RESPONSE))
                    .end();
        });
    }

    @Test
    public void shouldReturn404WhenAdapterNotExist(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .get(port, "localhost", "/api/adapters/toto")
                    .handler(resp -> {
                        testContext.assertTrue(404 == resp.statusCode());
                        async.complete();
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Cookie", "guard=" + ((JsonObject) res.result().body()).getString(Constant.RESPONSE))
                    .end();
        });
    }

    @Test
    public void shouldUpdateAdapter(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forAdapter().crud().insert(adapter1).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            adapter2.setId(adapter1.getId());
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .put(port, "localhost", "/api/adapters/" + adapter1.getId())
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        Adapter updated = resource.getManagerFactory().forAdapter().crud().findById(adapter1.getId()).get();
                        testContext.assertNotNull(updated);
                        testContext.assertEquals(adapter2.getName(), updated.getName());
                        testContext.assertEquals(adapter2.getDescription(), updated.getDescription());
                        async.complete();
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(adapter2).toString().length()))
                    .putHeader("Cookie", "guard=" + ((JsonObject) res.result().body()).getString(Constant.RESPONSE))
                    .write(JsonObject.mapFrom(adapter2).toBuffer())
                    .end();
        });
    }

    @Test
    public void shouldDeleteAdapter(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forAdapter().crud().insert(adapter1).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            adapter2.setId(adapter1.getId());
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .delete(port, "localhost", "/api/adapters/" + adapter1.getId())
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        testContext.assertNull(resource.getManagerFactory().forAdapter().crud().findById(adapter1.getId()).get());
                        async.complete();
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(adapter2).toString().length()))
                    .putHeader("Cookie", "guard=" + ((JsonObject) res.result().body()).getString(Constant.RESPONSE))
                    .write(JsonObject.mapFrom(adapter2).toBuffer())
                    .end();
        });
    }

}