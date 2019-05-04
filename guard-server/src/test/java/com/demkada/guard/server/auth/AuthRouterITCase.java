package com.demkada.guard.server.auth;

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
 */

import com.icegreen.greenmail.junit.GreenMailRule;
import com.icegreen.greenmail.store.FolderException;
import com.icegreen.greenmail.util.ServerSetupTest;
import com.demkada.guard.server.Guard;
import com.demkada.guard.server.commons.SecurityQuestion;
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
import org.hamcrest.Matchers;
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

import static fr.sii.ogham.assertion.OghamAssertions.assertThat;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.Matchers.emptyIterable;
import static org.hamcrest.core.Is.is;

@RunWith(VertxUnitRunner.class)
public class AuthRouterITCase {

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
    @Rule
    public final GreenMailRule greenMail = new GreenMailRule(ServerSetupTest.SMTP);


    private Vertx vertx;
    private User user1;
    private User user2;
    private int port;

    @Before
    public void SetUp(TestContext testContext) throws IOException, FolderException {
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
        user1.setPin("123456");

        user2 = new User();
        user2.setEmail("kadary.dembele@com.com");
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

        greenMail.purgeEmailFromAllMailboxes();

        vertx = Vertx.vertx();
        vertx.deployVerticle(
                Guard.class.getName(),
                new DeploymentOptions().setConfig(
                        new JsonObject()
                                .put(Constant.GUARD_HTTPS_PORT_CONFIG_KEY, port)
                                .put(Constant.CASSANDRA_CLUSTER_CONFIG_KEY, "127.0.0.1")
                                .put(Constant.CASSANDRA_CLUSTER_PORT_KEY, Integer.valueOf(resource.getNativeSession().getCluster().getMetadata().getAllHosts().toArray()[0].toString().split(":")[1]))
                                .put(Constant.SMTP_SERVER_HOST, ServerSetupTest.SMTP.getBindAddress())
                                .put(Constant.SMTP_SERVER_PORT, ServerSetupTest.SMTP.getPort())
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
    public void shouldRegisterUserWheInputIsCorrect(TestContext testContext) {
        Async async = testContext.async();
        JsonObject body = JsonObject.mapFrom(user1);
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/sign-up")
                .handler(resp -> {
                    testContext.assertTrue(201 == resp.statusCode());
                    assertThat(greenMail).receivedMessages()
                            .count(is(2))
                            .message(0)
                            .subject(is("Confirm your Guard account"))
                            .from()
                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                            .to()
                            .address(hasItems("kad.d@demkada.com")).and()
                            .body()
                            .contentAsString(containsString("https://localhost:8443/#/auth/confirm-email/"))
                            .contentType(startsWith("text/html")).and()
                            .alternative(nullValue())
                            .attachments(emptyIterable());
                    async.complete();
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(body.toString().length()))
                .write(body.toBuffer())
                .end();
    }

    @Test
    public void shouldNotRegisterUserWhenBadInput(TestContext testContext) {
        Async async = testContext.async();
        JsonObject body = JsonObject.mapFrom(user2);
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/sign-up")
                .handler(resp -> {
                    testContext.assertTrue(400 == resp.statusCode());
                    async.complete();
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(body.toString().length()))
                .write(body.toBuffer())
                .end();
    }

    @Test
    public void shouldNotRegisterSameUserMultiTime(TestContext testContext) {
        Async async = testContext.async();
        JsonObject body = JsonObject.mapFrom(user1);
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/sign-up")
                .handler(resp -> {
                    testContext.assertTrue(201 == resp.statusCode());
                    vertx.createHttpClient(new HttpClientOptions()
                            .setSsl(true)
                            .setVerifyHost(false)
                            .setTrustAll(true))
                            .post(port, "localhost", "/auth/sign-up")
                            .handler(r -> {
                                testContext.assertTrue(409 == r.statusCode());
                                async.complete();
                            })
                            .putHeader("Content-Type", "application/json")
                            .putHeader("Content-Length", String.valueOf(body.toString().length()))
                            .write(body.toBuffer())
                            .end();
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(body.toString().length()))
                .write(body.toBuffer())
                .end();
    }

    @Test
    public void shouldLoginWithCorrectCredsWhenEmailIsVerified(TestContext testContext) {
        Async async = testContext.async();
        JsonObject body = JsonObject.mapFrom(user1);
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/sign-up")
                .handler(resp -> {
                    testContext.assertTrue(201 == resp.statusCode());
                    JsonObject b = new JsonObject().put("email", user1.getEmail()).put("pwd", user1.getPwd());
                    User user = new User();
                    user.setEmail(user1.getEmail());
                    user.setEmailVerified(true);
                    AtomicReference<DeliveryOptions> options = new AtomicReference<>();
                    AtomicReference<JsonObject> entries = new AtomicReference<>();
                    options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_USER));
                    entries.set(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)));
                    vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), asyncResult -> {
                        testContext.assertTrue(asyncResult.succeeded());
                        vertx.createHttpClient(new HttpClientOptions()
                                .setSsl(true)
                                .setVerifyHost(false)
                                .setTrustAll(true))
                                .post(port, "localhost", "/auth/sign-in")
                                .handler(r -> {
                                    testContext.assertTrue(200 == r.statusCode());
                                    testContext.assertEquals(5, r.cookies().get(0).split("=")[1].split("\\.").length);
                                    async.complete();
                                })
                                .putHeader("Content-Type", "application/json")
                                .putHeader("Content-Length", String.valueOf(b.toString().length()))
                                .write(b.toBuffer())
                                .end();
                    });
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(body.toString().length()))
                .write(body.toBuffer())
                .end();
    }

    @Test
    public void shouldLogoutUser(TestContext testContext) {
        Async async = testContext.async();
        JsonObject body = JsonObject.mapFrom(user1);
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/sign-up")
                .handler(resp -> {
                    JsonObject b = new JsonObject().put("email", user1.getEmail()).put("pwd", user1.getPwd());
                    User user = new User();
                    user.setEmail(user1.getEmail());
                    user.setEmailVerified(true);
                    AtomicReference<DeliveryOptions> options = new AtomicReference<>();
                    AtomicReference<JsonObject> entries = new AtomicReference<>();
                    options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_USER));
                    entries.set(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)));
                    vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), asyncResult -> vertx.createHttpClient(new HttpClientOptions()
                            .setSsl(true)
                            .setVerifyHost(false)
                            .setTrustAll(true))
                            .post(port, "localhost", "/auth/sign-in")
                            .handler(r -> {
                                testContext.assertTrue(200 == r.statusCode());
                                vertx.createHttpClient(new HttpClientOptions()
                                        .setSsl(true)
                                        .setVerifyHost(false)
                                        .setTrustAll(true))
                                        .post(port, "localhost", "/auth/sign-out")
                                        .handler(s -> {
                                            testContext.assertTrue(200 == r.statusCode());
                                            async.complete();
                                        })
                                        .putHeader("Content-Type", "application/json")
                                        .end();
                            })
                            .putHeader("Content-Type", "application/json")
                            .putHeader("Content-Length", String.valueOf(b.toString().length()))
                            .write(b.toBuffer())
                            .end());
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(body.toString().length()))
                .write(body.toBuffer())
                .end();
    }

    @Test
    public void shouldNotLoginWithCorrectCredsWhenUserIsDisable(TestContext testContext) {
        Async async = testContext.async();
        JsonObject body = JsonObject.mapFrom(user1);
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/sign-up")
                .handler(resp -> {
                    testContext.assertTrue(201 == resp.statusCode());
                    JsonObject b = new JsonObject().put("email", user1.getEmail()).put("pwd", user1.getPwd());
                    User user = new User();
                    user.setEmail(user1.getEmail());
                    user.setDisable(true);
                    AtomicReference<DeliveryOptions> options = new AtomicReference<>();
                    AtomicReference<JsonObject> entries = new AtomicReference<>();
                    options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_USER));
                    entries.set(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)));
                    vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), asyncResult -> {
                        testContext.assertTrue(asyncResult.succeeded());
                        vertx.createHttpClient(new HttpClientOptions()
                                .setSsl(true)
                                .setVerifyHost(false)
                                .setTrustAll(true))
                                .post(port, "localhost", "/auth/sign-in")
                                .handler(r -> {
                                    testContext.assertTrue(401 == r.statusCode());
                                    async.complete();
                                })
                                .putHeader("Content-Type", "application/json")
                                .putHeader("Content-Length", String.valueOf(b.toString().length()))
                                .write(b.toBuffer())
                                .end();
                    });
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(body.toString().length()))
                .write(body.toBuffer())
                .end();
    }

    @Test
    public void shouldNotLoginWithCorrectCredsWhenEmailIsNotVerified(TestContext testContext) {
        Async async = testContext.async();
        JsonObject body = JsonObject.mapFrom(user1);
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/sign-up")
                .handler(resp -> {
                    testContext.assertTrue(201 == resp.statusCode());
                    JsonObject b = new JsonObject().put("email", user1.getEmail()).put("pwd", user1.getPwd());
                    vertx.createHttpClient(new HttpClientOptions()
                            .setSsl(true)
                            .setVerifyHost(false)
                            .setTrustAll(true))
                            .post(port, "localhost", "/auth/sign-in")
                            .handler(r -> {
                                testContext.assertTrue(403 == r.statusCode());
                                async.complete();
                            })
                            .putHeader("Content-Type", "application/json")
                            .putHeader("Content-Length", String.valueOf(b.toString().length()))
                            .write(b.toBuffer())
                            .end();
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(body.toString().length()))
                .write(body.toBuffer())
                .end();
    }

    @Test
    public void shouldGetSecQuestionsInEnglish(TestContext testContext) {
        Async async = testContext.async();
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/auth/security-questions")
                .handler(resp -> {
                    testContext.assertTrue(200 == resp.statusCode());
                    resp.bodyHandler(body -> {
                        JsonArray questions = body.toJsonArray();
                        testContext.assertEquals(5, questions.size());
                        testContext.assertTrue(questions.stream().anyMatch(o -> ((JsonObject) o).getString(QuestionId.PRIMARY_SCHOOL.name()).equalsIgnoreCase(new SecurityQuestion().getEnglishQuestions().get(QuestionId.PRIMARY_SCHOOL))));
                        async.complete();
                    });
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("accept-language", "pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7")
                .end();
    }

    @Test
    public void shouldGetSecQuestionsInFrench(TestContext testContext) {
        Async async = testContext.async();
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/auth/security-questions")
                .handler(resp -> {
                    testContext.assertTrue(200 == resp.statusCode());
                    resp.bodyHandler(body -> {
                        JsonArray questions = body.toJsonArray();
                        testContext.assertTrue(questions.stream().anyMatch(o -> ((JsonObject) o).getString(QuestionId.PRIMARY_SCHOOL.name()).equalsIgnoreCase(new SecurityQuestion().getFrenchQuestions().get(QuestionId.PRIMARY_SCHOOL))));
                        testContext.assertEquals(5, questions.size());
                        async.complete();
                    });
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("accept-language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7")
                .end();
    }

    @Test
    public void shouldAcceptPasswordResetWhenEmailIsVerified(TestContext testContext) {
        Async async = testContext.async();
        JsonObject body = JsonObject.mapFrom(user1);
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/sign-up")
                .handler(resp -> {
                    testContext.assertTrue(201 == resp.statusCode());
                    JsonObject b = new JsonObject().put("email", user1.getEmail());
                    User user = new User();
                    user.setEmail(user1.getEmail());
                    user.setEmailVerified(true);
                    AtomicReference<DeliveryOptions> options = new AtomicReference<>();
                    AtomicReference<JsonObject> entries = new AtomicReference<>();
                    options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_USER));
                    entries.set(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)));
                    vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries.get(), options.get(), asyncResult -> {
                        testContext.assertTrue(asyncResult.succeeded());
                        try {
                            greenMail.purgeEmailFromAllMailboxes();
                        } catch (FolderException e) {
                            e.printStackTrace();
                        }
                        vertx.createHttpClient(new HttpClientOptions()
                                .setSsl(true)
                                .setVerifyHost(false)
                                .setTrustAll(true))
                                .post(port, "localhost", "/auth/reset-password")
                                .handler(r -> {
                                    testContext.assertTrue(200 == r.statusCode());
                                    testContext.verify(v -> {
                                        assertThat(greenMail).receivedMessages()
                                                .count(is(2))
                                                .message(0)
                                                .subject(is("Your Guard account password reset request"))
                                                .from()
                                                .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                                                .to()
                                                .address(hasItems(user1.getEmail())).and()
                                                .body()
                                                .contentAsString(containsString("https://localhost:8443/#/auth/reset-password/"))
                                                .contentType(startsWith("text/html")).and()
                                                .alternative(nullValue())
                                                .attachments(emptyIterable());
                                        async.complete();
                                    });

                                })
                                .putHeader("Content-Type", "application/json")
                                .putHeader("Content-Length", String.valueOf(b.toString().length()))
                                .write(b.toBuffer())
                                .end();
                    });
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(body.toString().length()))
                .write(body.toBuffer())
                .end();
    }

    @Test
    public void shouldNotAcceptPasswordResetWhenEmailIsNotVerified(TestContext testContext) {
        Async async = testContext.async();
        JsonObject body = JsonObject.mapFrom(user1);
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/sign-up")
                .handler(resp -> {
                    testContext.assertTrue(201 == resp.statusCode());
                    JsonObject b = new JsonObject().put("email", user1.getEmail());
                    try {
                        greenMail.purgeEmailFromAllMailboxes();
                    } catch (FolderException e) {
                        e.printStackTrace();
                    }
                    vertx.createHttpClient(new HttpClientOptions()
                            .setSsl(true)
                            .setVerifyHost(false)
                            .setTrustAll(true))
                            .post(port, "localhost", "/auth/reset-password")
                            .handler(r -> {
                                testContext.assertTrue(200 == r.statusCode());
                                testContext.verify(v -> assertThat(greenMail).receivedMessages()
                                        .count(is(2))
                                        .message(0)
                                        .subject(is("Your Guard account password reset request"))
                                        .from()
                                        .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                                        .to()
                                        .address(hasItems("kad.d@demkada.com")).and()
                                        .body()
                                        .contentAsString(Matchers.containsString("However this email address is not known by Guard and therefore the attempt of password change has failed."))
                                        .contentType(startsWith("text/html")).and()
                                        .alternative(nullValue())
                                        .attachments(emptyIterable()));
                                async.complete();
                            })
                            .putHeader("Content-Type", "application/json")
                            .putHeader("Content-Length", String.valueOf(b.toString().length()))
                            .write(b.toBuffer())
                            .end();
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(body.toString().length()))
                .write(body.toBuffer())
                .end();
    }

    @Test
    public void shouldHandleValidPasswordResetLink(TestContext testContext) {
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
            entries.set(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 1L));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                testContext.assertTrue(res.succeeded());
                testContext.assertNotNull(res.result().body());
                JsonObject response = (JsonObject) res.result().body();
                String key = response.getString(Constant.RESPONSE);
                vertx.createHttpClient(new HttpClientOptions()
                        .setSsl(true)
                        .setVerifyHost(false)
                        .setTrustAll(true))
                        .get(port, "localhost", "/auth/reset-password/" + key)
                        .handler(resp -> {
                            testContext.assertTrue(200 == resp.statusCode());
                            resp.bodyHandler(body -> {
                                JsonArray questions = body.toJsonArray();
                                testContext.assertEquals(2, questions.size());
                                async.complete();
                            });
                        })
                        .putHeader("Content-Type", "application/json")
                        .end();
            });
        });
    }

    @Test
    public void shouldHandleValidPasswordChangeWhenSecQuesResponseAreValid(TestContext testContext) {
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
            entries.set(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 1L));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                testContext.assertTrue(res.succeeded());
                testContext.assertNotNull(res.result().body());
                JsonObject response = (JsonObject) res.result().body();
                String key = response.getString(Constant.RESPONSE);
                JsonObject payload = new JsonObject().put("pwd", "newPass").put("security_question", JsonObject.mapFrom(user1.getSecurityQuestion()));
                vertx.createHttpClient(new HttpClientOptions()
                        .setSsl(true)
                        .setVerifyHost(false)
                        .setTrustAll(true))
                        .post(port, "localhost", "/auth/reset-password/" + key)
                        .handler(resp -> {
                            testContext.assertTrue(200 == resp.statusCode());
                            User updated = resource.getManagerFactory().forUser().crud().findById(user.getEmail()).get();
                            StringHashUtil.validatePassword(vertx, "newPass", updated.getPwd(), p -> {
                                testContext.assertTrue(p.result());
                                async.complete();
                            });
                        })
                        .putHeader("Content-Type", "application/json")
                        .putHeader("Content-Length", String.valueOf(payload.toString().length()))
                        .write(payload.toBuffer())
                        .end();
            });
        });
    }

    @Test
    public void shouldNotHandleInvalidPasswordResetLink(TestContext testContext) {
        Async async = testContext.async();
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/auth/reset-password/toto")
                .handler(resp -> {
                    testContext.assertTrue(403 == resp.statusCode());
                    async.complete();
                })
                .putHeader("Content-Type", "application/json")
                .end();
    }

    @Test
    public void shouldSendConfirmationLink(TestContext testContext) {
        Async async = testContext.async();
        JsonObject body = JsonObject.mapFrom(user1);
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/sign-up")
                .handler(resp -> {
                    testContext.assertTrue(201 == resp.statusCode());
                    JsonObject b = new JsonObject().put("email", user1.getEmail());
                    try {
                        greenMail.purgeEmailFromAllMailboxes();
                    } catch (FolderException e) {
                        e.printStackTrace();
                    }
                    vertx.createHttpClient(new HttpClientOptions()
                            .setSsl(true)
                            .setVerifyHost(false)
                            .setTrustAll(true))
                            .post(port, "localhost", "/auth/confirm-email")
                            .handler(r -> {
                                testContext.assertTrue(200 == r.statusCode());
                                testContext.verify(v -> {
                                    assertThat(greenMail).receivedMessages()
                                            .count(is(2))
                                            .message(0)
                                            .subject(is("Confirm your Guard account"))
                                            .from()
                                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                                            .to()
                                            .address(hasItems("kad.d@demkada.com")).and()
                                            .body()
                                            .contentAsString(Matchers.containsString("https://localhost:8443/#/auth/confirm-email/"))
                                            .contentType(startsWith("text/html")).and()
                                            .alternative(nullValue())
                                            .attachments(emptyIterable());
                                    async.complete();
                                });

                            })
                            .putHeader("Content-Type", "application/json")
                            .putHeader("Content-Length", String.valueOf(b.toString().length()))
                            .write(b.toBuffer())
                            .end();
                })
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(body.toString().length()))
                .write(body.toBuffer())
                .end();
    }

    @Test
    public void shouldHandleEmailConfirmationResult(TestContext testContext) {
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
            entries.set(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user1)).put(Constant.EXP, 1L));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                testContext.assertTrue(res.succeeded());
                testContext.assertNotNull(res.result().body());
                JsonObject response = (JsonObject) res.result().body();
                String key = response.getString(Constant.RESPONSE);
                vertx.createHttpClient(new HttpClientOptions()
                        .setSsl(true)
                        .setVerifyHost(false)
                        .setTrustAll(true))
                        .get(port, "localhost", "/auth/confirm-email/" + key)
                        .handler(resp -> {
                            testContext.assertTrue(200 == resp.statusCode());
                            testContext.verify(v -> {
                                assertThat(greenMail).receivedMessages()
                                        .count(is(2))
                                        .message(0)
                                        .subject(is("Your Guard account has been verified"))
                                        .from()
                                        .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                                        .to()
                                        .address(hasItems("kad.d@demkada.com")).and()
                                        .body()
                                        .contentAsString(Matchers.containsString("Your Guard account has been verified, from now on you can connect to apps through Guard."))
                                        .contentType(startsWith("text/html")).and()
                                        .alternative(nullValue())
                                        .attachments(emptyIterable());
                                async.complete();

                            });
                        })
                        .putHeader("Content-Type", "application/json")
                        .end();
            });
        });
    }


}
