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
import com.demkada.guard.server.Guard;
import com.demkada.guard.server.commons.model.*;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.QueryString;
import com.demkada.guard.server.commons.utils.StringHashUtil;
import com.demkada.guard.server.commons.utils.Utils;
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
public class ConsentRouterITCase {

    static {
        System.setProperty("vertx.disableDnsResolver", "true");
    }

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
    private User user1;
    private User user2;
    private Client client1;
    private Consent consent1;
    private Consent consent2;
    private Consent consent3;
    private Consent consent4;
    private Scope internalCreateConsents;
    private Scope internalReadConsents;
    private Scope internalDeleteConsents;
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

        client1 = new Client();
        client1.setName("CloudCli");
        client1.setId("client_CloudCli");
        client1.setSecret("secret_CloudCli");
        client1.setRedirectUris(Collections.singleton("https://localhost:8443"));
        client1.setDescription("Created by CloudCli");

        consent1 = new Consent();
        consent1.setScopeName("scope1");
        consent1.setClientId("client1");
        consent1.setUserEmail(user1.getEmail());
        consent1.setClientName("client1");

        consent2 = new Consent();
        consent2.setScopeName("scope2");
        consent2.setClientId("client1");
        consent2.setUserEmail(user1.getEmail());
        consent2.setClientName("client1");

        consent3 = new Consent();
        consent3.setScopeName("scope1");
        consent3.setClientId("client1");
        consent3.setUserEmail(user2.getEmail());
        consent3.setClientName("client1");

        consent4 = new Consent();
        consent4.setScopeName("scope3");
        consent4.setClientId("client1");
        consent4.setUserEmail(user1.getEmail());
        consent4.setClientName("client1");

        Scope scope1 = new Scope();
        scope1.setName("scope1");
        scope1.setEnDescription("Scope 1 description");

        Scope scope2 = new Scope();
        scope2.setName("scope2");
        scope2.setEnDescription("Scope 2 description");

        resource.getManagerFactory().forScope().crud().insert(scope1).execute();
        resource.getManagerFactory().forScope().crud().insert(scope2).execute();

        internalCreateConsents = new Scope();
        internalCreateConsents.setName(InternalScope.GUARD_CREATE_CONSENTS.name());
        internalCreateConsents.setEnDescription("internalCreateConsents description");

        internalReadConsents = new Scope();
        internalReadConsents.setName(InternalScope.GUARD_READ_CONSENTS.name());
        internalReadConsents.setEnDescription("internalReadConsents description");

        internalDeleteConsents = new Scope();
        internalDeleteConsents.setName(InternalScope.GUARD_DELETE_CONSENTS.name());
        internalDeleteConsents.setEnDescription("internalDeleteConsents description");

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
                                .put(Constant.GUARD_OAUTH2_OPAQUE_ACCESS_TOKEN, true)
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
    public void shouldCreateConsentsFromUserCookie(TestContext testContext) {
        Async async = testContext.async();
        JsonArray array = new JsonArray().add(JsonObject.mapFrom(consent1)).add(JsonObject.mapFrom(consent2)).add(JsonObject.mapFrom(consent3));
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .post(port, "localhost", "/api/consents")
                    .handler(resp -> {
                        testContext.assertTrue(201 == resp.statusCode());
                        async.complete();
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Content-Length", String.valueOf(array.toString().length()))
                 .putHeader("Cookie", "guard=" + token)
                    .write(array.toBuffer())
                    .end();
        });
    }

    @Test
    public void shouldCreateConsentsFromBearerToken(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forScope().crud().insert(internalCreateConsents).execute();
        resource.getManagerFactory().forScope().crud().insert(internalReadConsents).execute();
        resource.getManagerFactory().forScope().crud().insert(internalDeleteConsents).execute();
        consent1.setUserEmail(user1.getEmail());
        consent2.setUserEmail(user1.getEmail());
        consent3.setUserEmail(user1.getEmail());
        JsonArray array = new JsonArray().add(JsonObject.mapFrom(consent1)).add(JsonObject.mapFrom(consent2)).add(JsonObject.mapFrom(consent3));
        QueryString body = new QueryString("grant_type", "client_credentials");
        body.add("scope", internalCreateConsents.getName());
        StringHashUtil.generateHash(vertx, client1.getSecret(), asyncResult -> {
            client1.setSecret(asyncResult.result());
            resource.getManagerFactory().forClient().crud().insert(client1).execute();
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .post(port, "localhost", "/oauth2/token")
                    .handler(tokenResult -> tokenResult.bodyHandler(b -> vertx.createHttpClient(new HttpClientOptions()
                            .setSsl(true)
                            .setVerifyHost(false)
                            .setTrustAll(true))
                            .post(port, "localhost", "/api/consents")
                            .handler(resp -> {
                                testContext.assertTrue(201 == resp.statusCode());
                                async.complete();
                            })
                            .putHeader("Content-Type", "application/json")
                            .putHeader("Content-Length", String.valueOf(array.toString().length()))
                            .putHeader("Authorization", "Bearer " +  b.toJsonObject().getString("access_token"))
                            .write(array.toBuffer())
                            .end()))
                    .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                    .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                    .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                    .write(Buffer.buffer(body.getQuery()))
                    .end();
        });
    }

    @Test
    public void shouldReturn400WhenInsertingJsonObjectInsteadOfJsonArray(TestContext testContext) {
        Async async = testContext.async();
        resource.getManagerFactory().forScope().crud().insert(internalCreateConsents).execute();
        consent1.setUserEmail(user1.getEmail());
        QueryString body = new QueryString("grant_type", "client_credentials");
        body.add("scope", internalCreateConsents.getName());
        StringHashUtil.generateHash(vertx, client1.getSecret(), asyncResult -> {
            client1.setSecret(asyncResult.result());
            resource.getManagerFactory().forClient().crud().insert(client1).execute();
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .post(port, "localhost", "/oauth2/token")
                    .handler(tokenResult -> tokenResult.bodyHandler(b -> vertx.createHttpClient(new HttpClientOptions()
                            .setSsl(true)
                            .setVerifyHost(false)
                            .setTrustAll(true))
                            .post(port, "localhost", "/api/consents")
                            .handler(resp -> {
                                testContext.assertTrue(400 == resp.statusCode());
                                async.complete();
                            })
                            .putHeader("Content-Type", "application/json")
                            .putHeader("Content-Length", String.valueOf(JsonObject.mapFrom(consent1).toString().length()))
                            .putHeader("Authorization", "Bearer " +  b.toJsonObject().getString("access_token"))
                            .write(JsonObject.mapFrom(consent1).toBuffer())
                            .end()))
                    .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                    .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                    .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                    .write(Buffer.buffer(body.getQuery()))
                    .end();
        });
    }

    @Test
    public void shouldNotCreateConsentWhenScopeDoesNotExist(TestContext testContext) {
        Async async = testContext.async();
        consent1.setScopeName("toto");
        JsonArray array = new JsonArray().add(JsonObject.mapFrom(consent1));
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .post(port, "localhost", "/api/consents")
                    .handler(resp -> {
                        testContext.assertTrue(500 == resp.statusCode());
                        resp.bodyHandler(b-> {
                            testContext.assertEquals("Scope does not exist" , b.toJsonObject().getString(Constant.ERROR_MESSAGE));
                            async.complete();
                        });
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Content-Length", String.valueOf(array.toString().length()))
                    .putHeader("Cookie", "guard=" + token)
                    .write(array.toBuffer())
                    .end();
        });
    }

    @Test
    public void shouldGetConsentsForConnectedUser(TestContext testContext) {
        Async async = testContext.async();
        Utils.encryptpk(vertx, user1.getEmail(), ar -> {
            if (ar.succeeded()) {
                consent1.setUserEmail(ar.result());
                consent2.setUserEmail(ar.result());
                consent4.setUserEmail(ar.result());
                resource.getManagerFactory().forConsent().crud().insert(consent1).execute();
                resource.getManagerFactory().forConsent().crud().insert(consent2).execute();
                resource.getManagerFactory().forConsent().crud().insert(consent4).execute();
                Utils.encryptpk(vertx, user2.getEmail(), asyncResult -> {
                    if (asyncResult.succeeded()) {
                        consent3.setUserEmail(asyncResult.result());
                        resource.getManagerFactory().forConsent().crud().insert(consent3).execute();
                        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
                        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 60L);
                        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
                            JsonObject response = (JsonObject) res.result().body();
                            String token = response.getString(Constant.RESPONSE);
                            vertx.createHttpClient(new HttpClientOptions()
                                    .setSsl(true)
                                    .setVerifyHost(false)
                                    .setTrustAll(true))
                                    .get(port, "localhost", "/api/consents")
                                    .handler(resp -> {
                                        testContext.assertTrue(200 == resp.statusCode());
                                        resp.bodyHandler(b -> {
                                            testContext.assertNotNull(b.toJsonArray());
                                            testContext.assertEquals(3, b.toJsonArray().size());
                                            testContext.assertTrue(b.toJsonArray().stream().allMatch(c ->{
                                                JsonObject o = (JsonObject) c;
                                                return !user2.getEmail().equalsIgnoreCase(o.getString("userEmail"));
                                            }));
                                            async.complete();
                                        });
                                    })
                                    .putHeader("Content-Type", "application/json")
                                 .putHeader("Cookie", "guard=" + token)
                                    .end();
                        });

                    }
                    else {
                        testContext.fail();
                    }
                });
            }
            else {
                testContext.fail();
            }
        });
    }

    @Test
    public void shouldGetEmptyConsentsListForConnectedUser(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            vertx.createHttpClient(new HttpClientOptions()
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true))
                    .get(port, "localhost", "/api/consents")
                    .handler(resp -> {
                        testContext.assertTrue(200 == resp.statusCode());
                        resp.bodyHandler(b -> {
                            testContext.assertNotNull(b.toJsonArray());
                            testContext.assertEquals(0, b.toJsonArray().size());
                            async.complete();
                        });
                    })
                    .putHeader("Content-Type", "application/json")
                    .putHeader("Cookie", "guard=" + token)
                    .end();
        });
    }

    @Test
    public void shouldGetConsentsByConnectedUserForSpecificScopesAndASpecifyClientId(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            Utils.encryptpk(vertx, user1.getEmail(), ar -> {
                if (ar.succeeded()) {
                    consent1.setUserEmail(ar.result());
                    consent2.setUserEmail(ar.result());
                    consent4.setUserEmail(ar.result());
                    resource.getManagerFactory().forConsent().crud().insert(consent1).execute();
                    resource.getManagerFactory().forConsent().crud().insert(consent2).execute();
                    resource.getManagerFactory().forConsent().crud().insert(consent4).execute();
                    Utils.encryptpk(vertx, user2.getEmail(), asyncResult -> {
                        if (asyncResult.succeeded()) {
                            consent3.setUserEmail(asyncResult.result());
                            resource.getManagerFactory().forConsent().crud().insert(consent3).execute();
                            vertx.createHttpClient(new HttpClientOptions()
                                    .setSsl(true)
                                    .setVerifyHost(false)
                                    .setTrustAll(true))
                                    .get(port, "localhost", "/api/consents?scope_name=" + consent1.getScopeName() + "&scope_name=" + consent2.getScopeName() + "&client_id=" + consent1.getClientId())
                                    .handler(resp -> {
                                        testContext.assertTrue(200 == resp.statusCode());
                                        resp.bodyHandler(b -> {
                                            testContext.assertNotNull(b.toJsonArray());
                                            testContext.assertEquals(2, b.toJsonArray().size());
                                            testContext.assertFalse(b.toJsonArray().stream().anyMatch(c ->{
                                                JsonObject o = (JsonObject) c;
                                                return user2.getEmail().equalsIgnoreCase(o.getString("userEmail"));
                                            }));
                                            async.complete();
                                        });
                                    })
                                    .putHeader("Content-Type", "application/json")
                                 .putHeader("Cookie", "guard=" + token)
                                    .end();

                        }
                        else {
                            testContext.fail();
                        }
                    });
                }
                else {
                    testContext.fail();
                }
            });
        });
    }

    @Test
    public void shouldGetAllConsentsWhenUserIsAdmin(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user2)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            Utils.encryptpk(vertx, user1.getEmail(), ar -> {
                if (ar.succeeded()) {
                    consent1.setUserEmail(ar.result());
                    consent2.setUserEmail(ar.result());
                    consent4.setUserEmail(ar.result());
                    resource.getManagerFactory().forConsent().crud().insert(consent1).execute();
                    resource.getManagerFactory().forConsent().crud().insert(consent2).execute();
                    resource.getManagerFactory().forConsent().crud().insert(consent4).execute();
                    Utils.encryptpk(vertx, user2.getEmail(), asyncResult -> {
                        if (asyncResult.succeeded()) {
                            consent3.setUserEmail(asyncResult.result());
                            resource.getManagerFactory().forConsent().crud().insert(consent3).execute();
                            vertx.createHttpClient(new HttpClientOptions()
                                    .setSsl(true)
                                    .setVerifyHost(false)
                                    .setTrustAll(true))
                                    .get(port, "localhost", "/api/consents")
                                    .handler(resp -> {
                                        testContext.assertTrue(200 == resp.statusCode());
                                        resp.bodyHandler(b -> {
                                            testContext.assertNotNull(b.toJsonArray());
                                            testContext.assertEquals(4, b.toJsonArray().size());
                                            testContext.assertTrue(b.toJsonArray().stream().anyMatch(c ->{
                                                JsonObject o = (JsonObject) c;
                                                return user2.getEmail().equalsIgnoreCase(o.getString("userEmail"));
                                            }));
                                            async.complete();
                                        });
                                    })
                                    .putHeader("Content-Type", "application/json")
                                 .putHeader("Cookie", "guard=" + token)
                                    .end();

                        }
                        else {
                            testContext.fail();
                        }
                    });
                }
                else {
                    testContext.fail();
                }
            });
        });
    }

    @Test
    public void shouldDeleteConsent(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            JsonObject response = (JsonObject) res.result().body();
            String token = response.getString(Constant.RESPONSE);
            Utils.encryptpk(vertx, user1.getEmail(), ar -> {
                if (ar.succeeded()) {
                    consent1.setUserEmail(ar.result());
                    consent2.setUserEmail(ar.result());
                    resource.getManagerFactory().forConsent().crud().insert(consent1).execute();
                    resource.getManagerFactory().forConsent().crud().insert(consent2).execute();
                    vertx.createHttpClient(new HttpClientOptions()
                            .setSsl(true)
                            .setVerifyHost(false)
                            .setTrustAll(true))
                            .delete(port, "localhost", "/api/consents?scope_name=" + consent1.getScopeName() + "&client_id=" + consent1.getClientId() + "&user_email=" + user1.getEmail())
                            .handler(resp -> {
                                testContext.assertTrue(200 == resp.statusCode());
                                PreparedStatement statement = resource.getManagerFactory().forConsent().getNativeSession().prepare("SELECT scope_name, user_email, client_id, timestamp, client_name FROM guard.consents_by_scope");
                                List<Consent> result =  resource.getManagerFactory().forConsent().raw().typedQueryForSelect(statement.bind()).getList();
                                testContext.assertNotNull(result);
                                testContext.assertEquals(1, result.size());
                                async.complete();
                            })
                            .putHeader("Content-Type", "application/json")
                         .putHeader("Cookie", "guard=" + token)
                            .end();
                }
                else {
                    testContext.fail();
                }
            });
        });
    }
}
