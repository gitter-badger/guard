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


import com.demkada.guard.server.commons.model.Adapter;
import com.demkada.guard.server.commons.model.AdapterType;
import com.demkada.guard.server.commons.utils.Constant;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.ManagerFactory_For_Guard;
import info.archinnov.achilles.junit.AchillesTestResource;
import info.archinnov.achilles.junit.AchillesTestResourceBuilder;
import io.vertx.core.DeploymentOptions;
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
public class AdapterManagerITCase {

    @Rule
    public AchillesTestResource<ManagerFactory_For_Guard> resource =  AchillesTestResourceBuilder
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
    private Adapter adapter1;
    private Adapter adapter2;

    @Before
    public void SetUp(TestContext testContext) {

        adapter1 = new Adapter();
        adapter1.setId("12345");
        adapter1.setName("SAS");
        adapter1.setType(AdapterType.OIDC);
        adapter1.setDescription("SAS OIDC adapter");
        adapter1.setAdapterUrl("https://sas.com");
        adapter1.setLogoUrl("https://sas.com/logo.png");

        adapter2 = new Adapter();
        adapter2.setId("ABCDE");
        adapter2.setName("SAFE");
        adapter2.setType(AdapterType.NATIVE);
        adapter2.setDescription("SAFE Native adapter");
        adapter2.setAdapterUrl("https://safe.com");
        adapter2.setLogoUrl("https://safe.com/logo.png");

        vertx = Vertx.vertx();
        vertx.deployVerticle(
                AdapterManager.class.getName(),
                new DeploymentOptions().setConfig(
                        new JsonObject()
                                .put(Constant.CASSANDRA_CLUSTER_CONFIG_KEY, "127.0.0.1")
                                .put(Constant.CASSANDRA_CLUSTER_PORT_KEY, Integer.valueOf(resource.getNativeSession().getCluster().getMetadata().getAllHosts().toArray()[0].toString().split(":")[1]))
                ),
                testContext.asyncAssertSuccess());
    }


    @After
    public void tearDown() {
        vertx.close();
    }

    @Test
    public void shouldInsertAdapter(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_ADAPTER);
        JsonObject entries = new JsonObject().put(Constant.ADAPTER, JsonObject.mapFrom(adapter1));
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            Adapter a = resource.getManagerFactory().forAdapter().crud().findById("12345").get();
            testContext.assertNotNull(a);
            testContext.assertEquals("SAS", a.getName());
            testContext.assertEquals("12345", a.getId());
            async.complete();
        });
    }

    @Test
    public void shouldGetAdapters(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forAdapter().crud().insert(adapter1).execute();
        resource.getManagerFactory().forAdapter().crud().insert(adapter2).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_ADAPTERS);
        JsonObject entries = new JsonObject();
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            List<Adapter> a = new ArrayList<>();
            JsonObject body = (JsonObject) res.result().body();
            JsonArray array = body.getJsonArray(Constant.RESPONSE);
            array.forEach(o -> {
                JsonObject object = (JsonObject) o;
                a.add(object.mapTo(Adapter.class));
            });
            testContext.assertNotNull(a);
            testContext.assertEquals(2, a.size());
            testContext.assertTrue(a.stream().anyMatch(client -> "12345".equalsIgnoreCase(client.getId())));
            testContext.assertTrue(a.stream().anyMatch(client -> "ABCDE".equalsIgnoreCase(client.getId())));
            async.complete();
        });
    }

    @Test
    public void shouldGetEmptyArray(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_ADAPTERS);
        JsonObject entries = new JsonObject();
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            testContext.assertEquals(0, ((JsonObject) res.result().body()).getJsonArray(Constant.RESPONSE).size());
            async.complete();
        });
    }

    @Test
    public void shouldGetAdapterById(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forAdapter().crud().insert(adapter1).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_ADAPTER_BY_ID);
        JsonObject entries = new JsonObject().put(Constant.ID, adapter1.getId());
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            Adapter a = ((JsonObject) res.result().body()).getJsonObject(Constant.RESPONSE).mapTo(Adapter.class);
            testContext.assertNotNull(a);
            testContext.assertEquals("12345", a.getId());
            async.complete();
        });
    }

    @Test
    public void shouldUpdateAdapter(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forAdapter().crud().insert(adapter1).execute();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_ADAPTER_BY_ID));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.ID, adapter1.getId()));
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            Adapter a = ((JsonObject) res.result().body()).getJsonObject(Constant.RESPONSE).mapTo(Adapter.class);
            testContext.assertNotNull(a);
            testContext.assertEquals("SAS", a.getName());
            testContext.assertEquals(adapter1.getDescription(), a.getDescription());
            adapter2.setId(adapter1.getId());
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_ADAPTER));
            entries.set(new JsonObject().put(Constant.ADAPTER, JsonObject.mapFrom(adapter2)));
            vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                testContext.assertTrue(reply.succeeded());
                testContext.assertNotNull(reply.result().body());
                Adapter updated = resource.getManagerFactory().forAdapter().crud().findById(adapter1.getId()).get();
                testContext.assertNotNull(updated);
                testContext.assertEquals(adapter2.getName(), updated.getName());
                testContext.assertEquals(adapter2.getDescription(), updated.getDescription());
                async.complete();
            });
        });
    }

    @Test
    public void shouldDeleteAdapter(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forAdapter().crud().insert(adapter1).execute();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DELETE_ADAPTER));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.ID, adapter1.getId()));
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNull(resource.getManagerFactory().forAdapter().crud().findById(adapter1.getId()).get());
            async.complete();
        });
    }
}