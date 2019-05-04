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


import com.demkada.guard.server.commons.model.Scope;
import com.demkada.guard.server.commons.utils.Constant;
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
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(VertxUnitRunner.class)
public class ScopeManagerITCase {

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
    private Scope scope1;
    private Scope scope2;
    private Scope scope3;

    @Before
    public void SetUp(TestContext testContext) {

        scope1 = new Scope();
        scope1.setName("scope1");
        scope1.setEnDescription("Scope 1 description");

        scope2 = new Scope();
        scope2.setName("scope2");
        scope2.setEnDescription("Scope 2 description");

        scope3 = new Scope();
        scope3.setName("scope3");
        scope3.setEnDescription("Scope 3 description");


        vertx = Vertx.vertx();
        io.vertx.core.Future<String> ScopeManagerFuture = io.vertx.core.Future.future();
        vertx.deployVerticle(
                ScopeManager.class.getName(),
                new DeploymentOptions().setConfig(
                        new JsonObject()
                                .put(Constant.CASSANDRA_CLUSTER_CONFIG_KEY, "127.0.0.1")
                                .put(Constant.CASSANDRA_CLUSTER_PORT_KEY, Integer.valueOf(resource.getNativeSession().getCluster().getMetadata().getAllHosts().toArray()[0].toString().split(":")[1]))
                ),
                ScopeManagerFuture.completer());

        Future<String> future = Future.future();
        ScopeManagerFuture.compose(v -> vertx.deployVerticle(CryptoManager.class.getName(), future.completer()), future);

        future.setHandler(testContext.asyncAssertSuccess());

    }

    @After
    public void tearDown() {
        vertx.close();
    }

    @Test
    public void shouldInsertScope(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_SCOPE);
        JsonObject entries = new JsonObject().put(Constant.SCOPE, JsonObject.mapFrom(scope1));
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            Scope s = resource.getManagerFactory().forScope().crud().findById("scope1").get();
            testContext.assertNotNull(s);
            testContext.assertEquals(scope1.getEnDescription(), s.getEnDescription());
            async.complete();
        });
    }

    @Test
    public void shouldGetAllScopes(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forScope().crud().insert(scope1).execute();
        resource.getManagerFactory().forScope().crud().insert(scope2).execute();
        resource.getManagerFactory().forScope().crud().insert(scope3).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPES);
        JsonObject entries = new JsonObject();
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            List<Scope> scopes = new ArrayList<>();
            JsonObject body = (JsonObject) res.result().body();
            JsonArray array = body.getJsonArray(Constant.RESPONSE);
            array.forEach(o -> {
                JsonObject object = (JsonObject) o;
                scopes.add(object.mapTo(Scope.class));
            });
            testContext.assertNotNull(scopes);
            testContext.assertEquals(3, scopes.size());
            testContext.assertTrue(scopes.stream().anyMatch(client -> "scope1".equalsIgnoreCase(client.getName())));
            testContext.assertTrue(scopes.stream().anyMatch(client -> "scope2".equalsIgnoreCase(client.getName())));
            testContext.assertTrue(scopes.stream().anyMatch(client -> "scope3".equalsIgnoreCase(client.getName())));
            async.complete();
        });
    }

    @Test
    public void shouldGetAllSpecifiedScopes(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPES);
        JsonObject entries = new JsonObject().put(Constant.SCOPE_NAME, new JsonArray(Arrays.asList("scope2", "scope3")));
        resource.getManagerFactory().forScope().crud().insert(scope1).execute();
        resource.getManagerFactory().forScope().crud().insert(scope2).execute();
        resource.getManagerFactory().forScope().crud().insert(scope3).execute();
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            List<Scope> scopes = new ArrayList<>();
            JsonObject body = (JsonObject) res.result().body();
            JsonArray array = body.getJsonArray(Constant.RESPONSE);
            array.forEach(o -> {
                JsonObject object = (JsonObject) o;
                scopes.add(object.mapTo(Scope.class));
            });
            testContext.assertNotNull(scopes);
            testContext.assertEquals(2, scopes.size());
            testContext.assertFalse(scopes.stream().anyMatch(client -> "scope1".equalsIgnoreCase(client.getName())));
            testContext.assertTrue(scopes.stream().anyMatch(client -> "scope2".equalsIgnoreCase(client.getName())));
            testContext.assertTrue(scopes.stream().anyMatch(client -> "scope3".equalsIgnoreCase(client.getName())));
            async.complete();
        });
    }

    @Test
    public void shouldGetScopeByName(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forScope().crud().insert(scope1).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPE_BY_NAME);
        JsonObject entries = new JsonObject().put(Constant.SCOPE_NAME, "scope1");
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject body = (JsonObject) res.result().body();
            Scope s = body.getJsonObject(Constant.RESPONSE).mapTo(Scope.class);
            testContext.assertNotNull(s);
            testContext.assertEquals(scope1.getName(), s.getName());
            async.complete();
        });
    }

    @Test
    public void shouldUpdateScope(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forScope().crud().insert(scope1).execute();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPE_BY_NAME));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.SCOPE_NAME, scope1.getName()));
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject body = (JsonObject) res.result().body();
            Scope s = body.getJsonObject(Constant.RESPONSE).mapTo(Scope.class);
            testContext.assertNotNull(s);
            testContext.assertEquals(scope1.getName(), s.getName());
            testContext.assertEquals(scope1.getEnDescription(), s.getEnDescription());

            scope2.setName(scope1.getName());
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_SCOPE));
            entries.set(new JsonObject().put(Constant.SCOPE, JsonObject.mapFrom(scope2)));
            vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                testContext.assertTrue(reply.succeeded());
                testContext.assertNotNull(reply.result().body());
                Scope updated = resource.getManagerFactory().forScope().crud().findById(scope1.getName()).get();
                testContext.assertNotNull(updated);
                testContext.assertEquals(scope2.getName(), updated.getName());
                testContext.assertEquals(scope2.getEnDescription(), updated.getEnDescription());
                async.complete();
            });
        });
    }

    @Test
    public void shouldDeleteScope(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forScope().crud().insert(scope2).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DELETE_SCOPE);
        JsonObject entries = new JsonObject().put(Constant.SCOPE_NAME, "scope2");
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            Scope updated = resource.getManagerFactory().forScope().crud().findById(scope2.getName()).get();
            testContext.assertNull(updated);
            async.complete();
        });
    }

}