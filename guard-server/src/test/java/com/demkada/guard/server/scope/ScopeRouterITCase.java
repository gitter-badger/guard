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


import com.demkada.guard.server.Guard;
import com.demkada.guard.server.commons.model.Scope;
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
import java.util.Collections;

@RunWith(VertxUnitRunner.class)
public class ScopeRouterITCase {
    static {
        System.setProperty("vertx.disableDnsResolver", "true");
    }

    @Rule
    public AchillesTestResource<ManagerFactory_For_Guard> resource =  AchillesTestResourceBuilder
            .forJunit()
            .withScript("guard.cql")
            .truncateBeforeAndAfterTest()
            .tablesToTruncate("users_by_email", "clients_by_id", "scopes_by_name", "consents_by_scope", "authz_code", "refresh_token")
            .tablesToTruncate("scopes_by_name", "users_by_email")
            .build((cluster, statementsCache) -> ManagerFactoryBuilder_For_Guard
                    .builder(cluster)
                    .doForceSchemaCreation(true)
                    .withDefaultKeyspaceName(Constant.GUARD)
                    .build()
            );

    private Vertx vertx;
    private User user;
    private Scope scope1;
    private Scope scope2;
    private Scope scope3;
    private int port;

    @Before
    public void SetUp(TestContext testContext) throws IOException {
        user = new User();
        user.setEmail("kad.d@demkada.com");
        user.setPwd("toto");
        user.setGivenName("Kad");
        user.setFamilyName("D.");

        scope1 = new Scope();
        scope1.setName("scope1");
        scope1.setEnDescription("Scope 1 description");
        scope1.setManagers(Collections.singleton(user.getEmail()));

        scope2 = new Scope();
        scope2.setName("scope2");
        scope2.setEnDescription("Scope 2 description");

        scope3 = new Scope();
        scope3.setName("scope3");
        scope3.setEnDescription("Scope 3 description");

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
                                .put(Constant.GUARD_SERVER_ADMIN, new JsonArray().add("kadary.dembele@demkada.com"))
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
    public void shouldCreateScope(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .post(port, "localhost", "/api/scopes")
                    .handler(resp -> {
                        testContext.assertTrue(201 == resp.statusCode());
                        resp.bodyHandler(b -> {
                            testContext.assertNotNull(b.toJsonObject());
                            testContext.assertNotNull(b.toJsonObject().getString("name"));
                            testContext.assertNotNull(b.toJsonObject().getString("enDescription"));
                            async.complete();
                        });
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(scope1).toString().length()))
                 .putHeader("Cookie", "guard=" + token)
                    .write(JsonObject.mapFrom(scope1).toBuffer())
                    .end();
        });
    }

    @Test
    public void shouldGetScopes(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forUser().crud().insert(user).execute();
        resource.getManagerFactory().forScope().crud().insert(scope1).execute();
        resource.getManagerFactory().forScope().crud().insert(scope2).execute();
        resource.getManagerFactory().forScope().crud().insert(scope3).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .get(port, "localhost", "/api/scopes?name=scope2&name=scope3")
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        resp.bodyHandler(b -> {
                            testContext.assertNotNull(b.toJsonArray());
                            testContext.assertEquals(2, b.toJsonArray().size());
                            testContext.assertTrue(b.toJsonArray().stream().allMatch(c ->{
                                JsonObject o = (JsonObject) c;
                                return !o.containsKey("restricted") && o.containsKey("endUserMFA");
                            }));
                            testContext.assertTrue(b.toJsonArray().stream().anyMatch(c ->{
                                JsonObject o = (JsonObject) c;
                                return scope3.getName().equalsIgnoreCase(o.getString("name"));
                            }));
                            async.complete();
                        });
                    })
                    .putHeader("Content-Type", "application/json")
                 .putHeader("Cookie", "guard=" + token)
                    .end();
        });
    }

    @Test
    public void shouldGetScopeByName(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forUser().crud().insert(user).execute();
        resource.getManagerFactory().forScope().crud().insert(scope3).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .get(port, "localhost", "/api/scopes/" + scope3.getName())
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        resp.bodyHandler(b -> {
                            testContext.assertNotNull(b.toJsonObject());
                            testContext.assertEquals(scope3.getName(), b.toJsonObject().getString("name"));
                            testContext.assertEquals(scope3.getEnDescription(), b.toJsonObject().getString("enDescription"));
                            async.complete();
                        });
                    })
                    .putHeader("Content-Type", "application/json")
                 .putHeader("Cookie", "guard=" + token)
                    .end();
        });
    }

    @Test
    public void shouldUpdateScope(TestContext testContext) {
        resource.getManagerFactory().forScope().crud().insert(scope1).execute();
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            scope3.setName(scope1.getName());
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .put(port, "localhost", "/api/scopes/" + scope1.getName())
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        Scope updated = resource.getManagerFactory().forScope().crud().findById(scope1.getName()).get();
                        testContext.assertNotNull(updated);
                        testContext.assertEquals(scope3.getEnDescription(), updated.getEnDescription());
                        async.complete();
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(scope3).toString().length()))
                 .putHeader("Cookie", "guard=" + token)
                    .write(JsonObject.mapFrom(scope3).toBuffer())
                    .end();
        });
    }

    @Test
    public void shouldDeleteScope(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            resource.getManagerFactory().forScope().crud().insert(scope1).execute();
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .delete(port, "localhost", "/api/scopes/" + scope1.getName())
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        vertx.createHttpClient(new HttpClientOptions()
                                .setSsl(true)
                                .setVerifyHost(false)
                                .setTrustAll(true))
                                .get(port, "localhost", "/api/scopes/" + scope1.getName())
                                .handler(r -> {
                                    testContext.assertTrue(404 == r.statusCode());
                                    async.complete();
                                })
                                .putHeader("Content-Type", "application/json")
                             .putHeader("Cookie", "guard=" + token)
                                .end();
                    })
                    .putHeader("Content-Type", "application/json")
                 .putHeader("Cookie", "guard=" + token)
                    .end();
        });
    }

}