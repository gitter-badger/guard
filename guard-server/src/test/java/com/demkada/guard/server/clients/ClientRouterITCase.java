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


import com.demkada.guard.server.Guard;
import com.demkada.guard.server.commons.model.*;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.QueryString;
import com.demkada.guard.server.commons.utils.StringHashUtil;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.ManagerFactory_For_Guard;
import info.archinnov.achilles.junit.AchillesTestResource;
import info.archinnov.achilles.junit.AchillesTestResourceBuilder;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
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
import java.util.*;

@RunWith(VertxUnitRunner.class)
public class ClientRouterITCase {

    static {
        System.setProperty("vertx.disableDnsResolver", "true");
    }

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
    private User user;
    private Client client1;
    private Client client2;
    private Client client3;
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
        Map<QuestionId, String>  secQ = new HashMap<>();
        secQ.put(QuestionId.CHILDHOOD_FRIEND, "Mon meilleur ami d'enfance");
        secQ.put(QuestionId.PRIMARY_SCHOOL, "Tu te souviens bien");
        user.setSecurityQuestion(secQ);

        client1 = new Client();
        client1.setName("CloudCli");
        client1.setId("client_CloudCli");
        client1.setSecret("secret_CloudCli");
        client1.setDescription("Created by CloudCli");
        client1.setManagers(Collections.singleton(user.getEmail()));
        client1.setLabels(Collections.singletonMap("key", "value"));

        client2 = new Client();
        client2.setName("Guard client");
        client2.setClientType(ClientType.CONFIDENTIAL);
        client2.setDescription("created by Guard");
        client2.setManagers(Collections.singleton("kadary.dembele@demkada.com"));
        client2.setRedirectUris(Collections.singleton("https://toto.com?my=1#kad"));
        client2.setLabels(Collections.singletonMap("key", "value"));


        client3 = new Client();
        client3.setId("disable_client");
        client3.setName("Guard client disable");
        client3.setDescription("created by Guard");
        client3.setManagers(Collections.singleton("kadary.dembele@demkada.com"));
        client3.setDisable(true);

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
    public void shouldCreateClient(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .post(port, "localhost", "/api/clients")
                    .handler(resp -> {
                        testContext.assertTrue(201 == resp.statusCode());
                        resp.bodyHandler(b -> {
                            testContext.assertNotNull(b.toJsonObject());
                            testContext.assertNotNull(b.toJsonObject().getString("id"));
                            testContext.assertNotNull(b.toJsonObject().getString("secret"));
                            async.complete();
                        });
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(client2).toString().length()))
                    .putHeader("Cookie", "guard=" + token)
                    .write(JsonObject.mapFrom(client2).toBuffer())
                    .end();
        });
    }
    @Test
    public void shouldReturn409WhenClientExist(TestContext testContext) {
        Async async = testContext.async();
        StringHashUtil.generateHash(vertx, client1.getSecret(), asyncResult -> {
            client1.setSecret(asyncResult.result());
            client2.setId("duplicated_client_test");
            client2.setSecret("toto");
            resource.getManagerFactory().forClient().crud().insert(client1).execute();
            QueryString body = new QueryString("grant_type", "client_credentials");
            body.add("scope", "GUARD_CREATE_CLIENTS");
            Scope scope = new Scope();
            scope.setName("GUARD_CREATE_CLIENTS");
            scope.setEnDescription("Scope description");
            scope.setRestricted(true);
            scope.setClientIdList(Collections.singleton(client1.getId()));
            scope.setManagers(new HashSet<>());
            resource.getManagerFactory().forScope().crud().insert(scope).execute();
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .post(port, "localhost", "/oauth2/token")
                    .handler(tokenResult -> {
                        testContext.assertTrue(200 == tokenResult.statusCode());
                        tokenResult.bodyHandler(b -> {
                            String token =   b.toJsonObject().getString("access_token");
                            vertx.createHttpClient(new HttpClientOptions()
                                    .setSsl(true)
                                    .setVerifyHost(false)
                                    .setTrustAll(true))
                                    .post(port, "localhost", "/api/clients")
                                    .handler(resp -> {
                                        vertx.createHttpClient(new HttpClientOptions()
                                                .setSsl(true)
                                                .setVerifyHost(false)
                                                .setTrustAll(true))
                                                .post(port, "localhost", "/api/clients")
                                                .handler(reply -> {
                                                    testContext.assertTrue(409 == reply.statusCode());
                                                    async.complete();
                                                })
                                                .putHeader("Content-Type", "application/json")
                                                .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(client2).toString().length()))
                                                .putHeader("Authorization", "Bearer " + token)
                                                .write(JsonObject.mapFrom(client2).toBuffer())
                                                .end();
                                    })
                                    .putHeader("Content-Type", "application/json")
                                    .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(client2).toString().length()))
                                    .putHeader("Authorization", "Bearer " + token)
                                    .write(JsonObject.mapFrom(client2).toBuffer())
                                    .end();
                        });
                    })
                    .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                    .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                    .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                    .write(Buffer.buffer(body.getQuery()))
                    .end();
        });
    }

    @Test
    public void shouldGetClients(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forUser().crud().insert(user).execute();
        resource.getManagerFactory().forClient().crud().insert(client1).execute();
        resource.getManagerFactory().forClient().crud().insert(client3).execute();
        client2.setId("tototot");
        resource.getManagerFactory().forClient().crud().insert(client2).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .get(port, "localhost", "/api/clients")
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        resp.bodyHandler(b -> {
                            testContext.assertNotNull(b.toJsonArray());
                            testContext.assertEquals(2, b.toJsonArray().size());
                            testContext.assertTrue(b.toJsonArray().stream().allMatch(c ->{
                                JsonObject o = (JsonObject) c;
                                return !o.containsKey("secret");
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
    public void shouldGetClientById(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forUser().crud().insert(user).execute();
        resource.getManagerFactory().forClient().crud().insert(client1).execute();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .get(port, "localhost", "/api/clients/" + client1.getId())
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        resp.bodyHandler(b -> {
                            testContext.assertNotNull(b.toJsonObject());
                            testContext.assertEquals(client1.getId(), b.toJsonObject().getString("id"));
                            testContext.assertEquals(client1.getName(), b.toJsonObject().getString("name"));
                            async.complete();
                        });
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Cookie", "guard=" + token)
                    .end();
        });
    }

    @Test
    public void shouldUpdateClientWithCookie(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            resource.getManagerFactory().forClient().crud().insert(client1).execute();
            client2.setId(client1.getId());
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .put(port, "localhost", "/api/clients/" + client1.getId())
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        Client updated = resource.getManagerFactory().forClient().crud().findById(client1.getId()).get();
                        testContext.assertNotNull(updated);
                        testContext.assertEquals(client2.getName(), updated.getName());
                        testContext.assertEquals(client2.getDescription(), updated.getDescription());
                        async.complete();
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(client2).toString().length()))
                    .putHeader("Cookie", "guard=" + token)
                    .write(JsonObject.mapFrom(client2).toBuffer())
                    .end();
        });
    }

    @Test
    public void shouldUpdateClientWithBearerToken(TestContext testContext) {
        Async async = testContext.async();
        StringHashUtil.generateHash(vertx, client1.getSecret(), asyncResult -> {
            client1.setSecret(asyncResult.result());
            resource.getManagerFactory().forClient().crud().insert(client1).execute();
            QueryString body = new QueryString("grant_type", "client_credentials");
            body.add("scope", "GUARD_UPDATE_CLIENTS");
            Scope scope = new Scope();
            scope.setName("GUARD_UPDATE_CLIENTS");
            scope.setEnDescription("Scope description");
            scope.setRestricted(true);
            scope.setClientIdList(Collections.singleton(client1.getId()));
            scope.setManagers(new HashSet<>());
            resource.getManagerFactory().forScope().crud().insert(scope).execute();
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .post(port, "localhost", "/oauth2/token")
                    .handler(tokenResult -> {
                        testContext.assertTrue(200 == tokenResult.statusCode());
                        tokenResult.bodyHandler(b -> {
                            String token =   b.toJsonObject().getString("access_token");
                            client2.setId(client1.getId());
                            vertx.createHttpClient(new HttpClientOptions()
                                    .setSsl(true)
                                    .setVerifyHost(false)
                                    .setTrustAll(true))
                                    .put(port, "localhost", "/api/clients/" + client1.getId())
                                    .handler(resp -> {
                                        testContext.assertTrue(200 == resp.statusCode());
                                        Client updated = resource.getManagerFactory().forClient().crud().findById(client1.getId()).get();
                                        testContext.assertNotNull(updated);
                                        testContext.assertEquals(client2.getDescription(), updated.getDescription());
                                        testContext.assertEquals(client2.getName(), updated.getName());
                                        async.complete();
                                    })
                                    .putHeader("Content-Type", "application/json")
                                    .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(client2).toString().length()))
                                    .putHeader("Authorization", "Bearer " + token)
                                    .write(JsonObject.mapFrom(client2).toBuffer())
                                    .end();
                        });
                    })
                    .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                    .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                    .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                    .write(Buffer.buffer(body.getQuery()))
                    .end();
        });
    }

    @Test
    public void shouldUpdateClientAndOverloadClientSecretWithBearerToken(TestContext testContext) {
        Async async = testContext.async();
        StringHashUtil.generateHash(vertx, client1.getSecret(), asyncResult -> {
            client1.setSecret(asyncResult.result());
            resource.getManagerFactory().forClient().crud().insert(client1).execute();
            QueryString body = new QueryString("grant_type", "client_credentials");
            body.add("scope", "GUARD_UPDATE_CLIENTS");
            Scope scope = new Scope();
            scope.setName("GUARD_UPDATE_CLIENTS");
            scope.setEnDescription("Scope description");
            scope.setRestricted(true);
            scope.setClientIdList(Collections.singleton(client1.getId()));
            scope.setManagers(new HashSet<>());
            resource.getManagerFactory().forScope().crud().insert(scope).execute();
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .post(port, "localhost", "/oauth2/token")
                    .handler(tokenResult -> {
                        testContext.assertTrue(200 == tokenResult.statusCode());
                        tokenResult.bodyHandler(b -> {
                            String token =   b.toJsonObject().getString("access_token");
                            client2.setId(client1.getId());
                            client2.setSecret("overloaded_secret");
                            vertx.createHttpClient(new HttpClientOptions()
                                    .setSsl(true)
                                    .setVerifyHost(false)
                                    .setTrustAll(true))
                                    .put(port, "localhost", "/api/clients/" + client1.getId())
                                    .handler(resp -> {
                                        testContext.assertTrue(200 == resp.statusCode());
                                        Client updated = resource.getManagerFactory().forClient().crud().findById(client1.getId()).get();
                                        StringHashUtil.validatePassword(vertx, client2.getSecret(), updated.getSecret(), r -> {
                                            testContext.assertTrue(r.result());
                                            async.complete();
                                        });
                                    })
                                    .putHeader("Content-Type", "application/json")
                                    .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(client2).toString().length()))
                                    .putHeader("Authorization", "Bearer " + token)
                                    .write(JsonObject.mapFrom(client2).toBuffer())
                                    .end();
                        });
                    })
                    .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                    .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                    .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                    .write(Buffer.buffer(body.getQuery()))
                    .end();
        });
    }


    @Test
    public void shouldDisableClient(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            resource.getManagerFactory().forClient().crud().insert(client1).execute();
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .delete(port, "localhost", "/api/clients/" + client1.getId())
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        vertx.createHttpClient(new HttpClientOptions()
                                .setSsl(true)
                                .setVerifyHost(false)
                                .setTrustAll(true))
                                .get(port, "localhost", "/api/clients/" + client1.getId())
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

    @Test
    public void shouldRestoreClient(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        user.setEmail("kadary.dembele@demkada.com");
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            resource.getManagerFactory().forClient().crud().insert(client3).execute();
            JsonObject body = new JsonObject().put(Constant.STATUS, false);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .put(port, "localhost", "/api/clients/" + client3.getId() + "/status")
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        testContext.assertFalse(resource.getManagerFactory().forClient().crud().findById(client3.getId()).get().isDisable());
                        async.complete();
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Content-Length", String.valueOf(body.toString().length()))
                    .putHeader("Cookie", "guard=" + token)
                    .write(body.toBuffer())
                    .end();
        });
    }

    @Test
    public void shouldGenerateNewSecret(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            resource.getManagerFactory().forClient().crud().insert(client1).execute();
            testContext.assertEquals("secret_CloudCli", client1.getSecret());
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .put(port, "localhost", "/api/clients/" + client1.getId() + "/secret")
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        resp.bodyHandler(b -> {
                            testContext.assertNotEquals("secret_CloudCli", b.toJsonObject().getString(Constant.CLIENT_SECRET));
                            async.complete();
                        });
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Cookie", "guard=" + token)
                    .end();
        });
    }

}
