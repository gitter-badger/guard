package com.demkada.guard.server.clients;

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


import com.demkada.guard.server.commons.model.Client;
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
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(VertxUnitRunner.class)
public class ClientManagerITCase {

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
    private Client client1;
    private Client client2;

    @Before
    public void SetUp(TestContext testContext) {

        client1 = new Client();
        client1.setName("CloudCli");
        client1.setId("client_CloudCli");
        client1.setSecret("secret_CloudCli");
        client1.setDescription("Created by CloudCli");

        client2 = new Client();
        client2.setName("Guard client");
        client2.setId("client_guard");
        client2.setDescription("created by Guard");
        client2.setManagers(Collections.singleton("kadary.dembele@demkada.com"));

        vertx = Vertx.vertx();
        io.vertx.core.Future<String> ClientManagerFuture = io.vertx.core.Future.future();
        vertx.deployVerticle(
                ClientManager.class.getName(),
                new DeploymentOptions().setConfig(
                        new JsonObject()
                                .put(Constant.CASSANDRA_CLUSTER_CONFIG_KEY, "127.0.0.1")
                                .put(Constant.CASSANDRA_CLUSTER_PORT_KEY, Integer.valueOf(resource.getNativeSession().getCluster().getMetadata().getAllHosts().toArray()[0].toString().split(":")[1]))
                ),
                ClientManagerFuture.completer());

        Future<String> future = Future.future();
        ClientManagerFuture.compose(v -> vertx.deployVerticle(CryptoManager.class.getName(), future.completer()), future);

        future.setHandler(testContext.asyncAssertSuccess());

    }

    @After
    public void tearDown() {
        vertx.close();
    }

    @Test
    public void shouldInsertClient(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_CLIENT);
        JsonObject entries = new JsonObject().put(Constant.CLIENT, JsonObject.mapFrom(client1));
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            Client c = resource.getManagerFactory().forClient().crud().findById("client_CloudCli").get();
            testContext.assertNotNull(c);
            testContext.assertEquals("CloudCli", c.getName());
            testContext.assertEquals("client_CloudCli", c.getId());
            testContext.assertNotEquals("secret_CloudCli", c.getSecret());
            StringHashUtil.validatePassword(vertx,"secret_CloudCli", c.getSecret(), r -> {
                testContext.assertTrue(r.result());
                async.complete();
            });
        });
    }

    @Test
    public void shouldFailWhenClientAlreadyExist(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_CLIENT);
        JsonObject entries = new JsonObject().put(Constant.CLIENT, JsonObject.mapFrom(client1));
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, res -> {
            vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, reply -> {
                testContext.assertTrue(reply.failed());
                async.complete();
            });
        });
    }

    @Test
    public void shouldGetClients(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forClient().crud().insert(client1).execute();
        resource.getManagerFactory().forClient().crud().insert(client2).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENTS);
        JsonObject entries = new JsonObject();
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            List<Client> c = new ArrayList<>();
            JsonObject body = (JsonObject) res.result().body();
            JsonArray array = body.getJsonArray(Constant.RESPONSE);
            array.forEach(o -> {
                JsonObject object = (JsonObject) o;
                c.add(object.mapTo(Client.class));
            });
            testContext.assertNotNull(c);
            testContext.assertEquals(2, c.size());
            testContext.assertTrue(c.stream().anyMatch(client -> "CloudCli".equalsIgnoreCase(client.getName())));
            testContext.assertTrue(c.stream().anyMatch(client -> "Guard client".equalsIgnoreCase(client.getName())));
            async.complete();
        });
    }

    @Test
    public void shouldGetEmptyArray(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENTS);
        JsonObject entries = new JsonObject();
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject body = (JsonObject) res.result().body();
            JsonArray array = body.getJsonArray(Constant.RESPONSE);
            testContext.assertEquals(0, array.size());
            async.complete();
        });
    }


    @Test
    public void shouldGetClientById(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forClient().crud().insert(client1).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENT_BY_ID);
        JsonObject entries = new JsonObject().put(Constant.CLIENT_ID, client1.getId());
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject body = (JsonObject) res.result().body();
            Client c = body.getJsonObject(Constant.RESPONSE).mapTo(Client.class);
            testContext.assertNotNull(c);
            testContext.assertEquals("CloudCli", c.getName());
            testContext.assertEquals("Created by CloudCli", c.getDescription());
            async.complete();
        });
    }

    @Test
    public void shouldUpdateClient(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forClient().crud().insert(client1).execute();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENT_BY_ID));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.CLIENT_ID, client1.getId()));
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject body = (JsonObject) res.result().body();
            Client c = body.getJsonObject(Constant.RESPONSE).mapTo(Client.class);
            testContext.assertNotNull(c);
            testContext.assertEquals("CloudCli", c.getName());
            testContext.assertEquals("Created by CloudCli", c.getDescription());

            client2.setId(client1.getId());
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_CLIENT));
            entries.set(new JsonObject().put(Constant.CLIENT, JsonObject.mapFrom(client2)));
            vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                testContext.assertTrue(reply.succeeded());
                testContext.assertNotNull(reply.result().body());
                Client updated = resource.getManagerFactory().forClient().crud().findById(client1.getId()).get();
                testContext.assertNotNull(updated);
                testContext.assertEquals("Guard client", updated.getName());
                testContext.assertEquals("created by Guard", updated.getDescription());
                async.complete();
            });
        });
    }

    @Test
    public void shouldChangeClientStatus(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forClient().crud().insert(client1).execute();
        Client c = resource.getManagerFactory().forClient().crud().findById(client1.getId()).get();
        testContext.assertFalse(c.isDisable());
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_CLIENT_STATUS);
        JsonObject entries = new JsonObject().put(Constant.CLIENT_ID, client1.getId())
                .put(Constant.STATUS, true);
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            Client updated = resource.getManagerFactory().forClient().crud().findById(client1.getId()).get();
            testContext.assertNotNull(updated);
            testContext.assertTrue(updated.isDisable());
            async.complete();
        });
    }

    @Test
    public void shouldChangeSecret(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_CLIENT));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.CLIENT, JsonObject.mapFrom(client1)));
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            Client c = resource.getManagerFactory().forClient().crud().findById(client1.getId()).get();
            StringHashUtil.validatePassword(vertx, "secret_CloudCli", c.getSecret(), r -> {
                testContext.assertTrue(r.result());
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_SECRET));
                entries.set(new JsonObject().put(Constant.CLIENT_ID, client1.getId())
                        .put(Constant.CLIENT_SECRET, "new_secret"));
                vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                    testContext.assertTrue(reply.succeeded());
                    testContext.assertNotNull(reply.result().body());
                    Client updated = resource.getManagerFactory().forClient().crud().findById(client1.getId()).get();
                    StringHashUtil.validatePassword(vertx, "secret_CloudCli", updated.getSecret(), p -> {
                        testContext.assertFalse(p.result());
                        StringHashUtil.validatePassword(vertx, "new_secret", updated.getSecret(), p1 -> {
                            testContext.assertTrue(p1.result());
                            async.complete();
                        });
                    });
                });
            });
        });
    }

}