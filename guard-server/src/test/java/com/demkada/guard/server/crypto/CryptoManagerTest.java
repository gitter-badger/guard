package com.demkada.guard.server.crypto;

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


import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.model.User;
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
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.atomic.AtomicReference;

@RunWith(VertxUnitRunner.class)
public class CryptoManagerTest {

    private Vertx vertx;
    private User user;


    @Before
    public void setUp(TestContext testContext) {
        user = new User();
        user.setEmail("kad.d@demkada.com");
        user.setSub("12345");
        user.setIdOrigin(Constant.GUARD);
        user.setPwd("toto");
        user.setAddress("Paris");
        user.setPhoneNumber("0000");
        user.setGivenName("Kad");
        user.setFamilyName("D.");

        vertx = Vertx.vertx();
        vertx.deployVerticle(
                CryptoManager.class.getName(),
                new DeploymentOptions()
                        .setConfig(new JsonObject()
                                .put(Constant.GUARD_KMIP_SERVER, false)
                                .put(Constant.GUARD_KMIP_SERVER_USER_LOGIN, "ksc-dev-app-kmip")
                                .put(Constant.GUARD_KMIP_SERVER_USER_PASS, "Koulpat@01022016")
                                .put(Constant.GUARD_KMIP_SERVER_HOST, "dkschsm01.dns21.com")
                                .put(Constant.GUARD_KMIP_SERVER_PORT, 5696)
                                .put(Constant.GUARD_KMIP_SERVER_KEYSTORE_PATH, "ksc-dev-app-kmip.jks")
                                .put(Constant.GUARD_KMIP_SERVER_KEYSTORE_PASS, "oL1hregPm0hj")
                                .put(Constant.GUARD_KMIP_SERVER_KEYSTORE_CERT_ALIAS, "ksc-dev-app-kmip")
                                .put(Constant.GUARD_KMIP_SERVER_RSA_PRIVATE_KEY, "ksc-all-dev-cle_test_rsa2048")
                                .put(Constant.GUARD_KMIP_SERVER_AES_PK_CIPHER_KEY, "ksc-all-dev-cle_test_aes128")
                                .put(Constant.GUARD_KMIP_SERVER_AES_DATA_CIPHER_KEY, "ksc-all-dev-cle_test_aes128")
                        ),
                testContext.asyncAssertSuccess());
    }

    @After
    public void tearDown() {
        vertx.close();
    }

    @Test
    public void shouldCipherPk(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_PRIMARY_KEY));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, user.getEmail()));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertNotEquals(user.getEmail(), response.getString(Constant.RESPONSE));
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_PRIMARY_KEY));
            entries.set(new JsonObject().put(Constant.PAYLOAD, response.getString(Constant.RESPONSE)));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                testContext.assertTrue(reply.succeeded());
                testContext.assertNotNull(reply.result().body());
                JsonObject resp = (JsonObject) reply.result().body();
                testContext.assertEquals(user.getEmail(), resp.getString(Constant.RESPONSE));
                async.complete();
            });
        });
    }

    @Test
    public void shouldGenerateTheSamePkCipherTextForSamePlainPk(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_PRIMARY_KEY));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, user.getEmail()));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertNotEquals(user.getEmail(), response.getString(Constant.RESPONSE));
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_PRIMARY_KEY));
            entries.set(new JsonObject().put(Constant.PAYLOAD, user.getEmail()));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                testContext.assertTrue(reply.succeeded());
                testContext.assertNotNull(reply.result().body());
                JsonObject resp = (JsonObject) reply.result().body();
                testContext.assertNotEquals(user.getEmail(), resp.getString(Constant.RESPONSE));
                testContext.assertEquals(response.getString(Constant.RESPONSE), resp.getString(Constant.RESPONSE));
                async.complete();
            });
        });
    }

    @Test
    public void shouldCipherSet(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_STRING_SET));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(user.getEmail())));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertNotEquals(user.getEmail(), response.getJsonArray(Constant.RESPONSE).getString(0));
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_STRING_SET));
            entries.set(new JsonObject().put(Constant.PAYLOAD, response.getJsonArray(Constant.RESPONSE)));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                testContext.assertTrue(reply.succeeded());
                testContext.assertNotNull(reply.result().body());
                JsonObject resp = (JsonObject) reply.result().body();
                testContext.assertEquals(user.getEmail(), resp.getJsonArray(Constant.RESPONSE).getString(0));
                async.complete();
            });
        });
    }

    @Test
    public void shouldNotGenerateTheSameSetCipherTextForSamePlainSet(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_STRING_SET));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(user.getEmail())));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertNotEquals(user.getEmail(), response.getJsonArray(Constant.RESPONSE).getString(0));
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_STRING_SET));
            entries.set(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(user.getEmail())));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                testContext.assertTrue(reply.succeeded());
                testContext.assertNotNull(reply.result().body());
                JsonObject resp = (JsonObject) reply.result().body();
                testContext.assertNotEquals(user.getEmail(), resp.getJsonArray(Constant.RESPONSE).getString(0));
                testContext.assertNotEquals(response.getJsonArray(Constant.RESPONSE).getString(0), resp.getJsonArray(Constant.RESPONSE).getString(0));
                async.complete();
            });
        });
    }

    @Test
    public void shouldGenerateUserToken(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            testContext.assertEquals(3, ((JsonObject) res.result().body()).getString(Constant.RESPONSE).split("\\.").length);
            async.complete();
        });
    }

    @Test
    public void shouldValidateUserToken(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_USER_TOKEN));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 60L));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result());
            JsonObject response = (JsonObject) res.result().body();
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_TOKEN));
            entries.set(new JsonObject().put(Constant.PAYLOAD, response.getString(Constant.RESPONSE)));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                testContext.assertTrue(reply.succeeded());
                testContext.assertNotNull(reply.result().body());
                JsonObject resp = (JsonObject) reply.result().body();
                testContext.assertEquals("Kad", resp.getJsonObject(Constant.RESPONSE).getString(Constant.GIVEN_NAME));
                async.complete();
            });
        });
    }

    @Test
    public void shouldNotValidateBadUserToken(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.PAYLOAD, "toto");
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, reply -> {
            testContext.assertFalse(reply.succeeded());
            testContext.assertNull(reply.result());
            testContext.assertNotNull(reply.cause());
            async.complete();
        });
    }

    @Test
    public void shouldGenerateEncryptedUserToken(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 1L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertEquals(5, response.getString(Constant.RESPONSE).split("\\.").length);
            async.complete();
        });
    }

    @Test
    public void shouldValidateEncryptedUserToken(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 1L));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            JsonObject response = (JsonObject) res.result().body();
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN));
            entries.set(new JsonObject().put(Constant.PAYLOAD, response.getString(Constant.RESPONSE)));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                testContext.assertTrue(reply.succeeded());
                testContext.assertNotNull(reply.result().body());
                JsonObject resp = (JsonObject) reply.result().body();
                testContext.assertEquals("D.", resp.getJsonObject(Constant.RESPONSE).getString(Constant.FAMILY_NAME));
                async.complete();
            });
        });
    }

    @Test
    public void shouldNotValidateBadEncryptedUserToken(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, "toto"));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            testContext.assertFalse(reply.succeeded());
            testContext.assertNull(reply.result());
            testContext.assertNotNull(reply.cause());
            async.complete();
        });
    }

    @Test
    public void shouldEncryptString(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_STRING);
        JsonObject entries = new JsonObject().put(Constant.PAYLOAD, "toto");
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertTrue(response.getString(Constant.RESPONSE).split("\\.").length == 5);
            async.complete();
        });
    }

    @Test
    public void shouldDecryptString(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_STRING));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, "toto"));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            testContext.assertTrue(res.succeeded());
            JsonObject response = (JsonObject) res.result().body();
            entries.set(new JsonObject().put(Constant.PAYLOAD, response.getString(Constant.RESPONSE)));
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_STRING));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), r -> {
                testContext.assertTrue(r.succeeded());
                JsonObject resp = (JsonObject) r.result().body();
                testContext.assertEquals("toto", resp.getString(Constant.RESPONSE));
                async.complete();
            });
        });
    }

    @Test
    public void shouldNotDecryptBadString(TestContext testContext) {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_STRING));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, "toto"));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), r -> {
            testContext.assertFalse(r.succeeded());
            testContext.assertNotNull(r.cause());
            testContext.assertNull(r.result());
            async.complete();
        });
    }

}