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
 *
 * @author <a href="mailto:kad@demkada.com">Kad D.</a>
*/


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.demkada.guard.server.Guard;
import com.demkada.guard.server.commons.model.Adapter;
import com.demkada.guard.server.commons.model.AdapterType;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.QueryString;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.ManagerFactory_For_Guard;
import info.archinnov.achilles.junit.AchillesTestResource;
import info.archinnov.achilles.junit.AchillesTestResourceBuilder;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.ServerSocket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(VertxUnitRunner.class)
public class OIDCAdapterITCase {
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
    private Adapter adapter;
    private int port;
    private KeyPair keyPair;

    @Before
    public void SetUp(TestContext testContext) throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
        adapter = new Adapter();
        adapter.setId("12345");
        adapter.setName("SAS");
        adapter.setType(AdapterType.OIDC);
        adapter.setDescription("SAS OIDC adapter");
        adapter.setClientId("xyz");
        adapter.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        adapter.setAdapterUrl("https://sas.com");
        adapter.setLogoUrl("https://sas.com/logo.png");
        resource.getManagerFactory().forAdapter().crud().insert(adapter).execute();

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

                ), testContext.asyncAssertSuccess());
    }

    @After
    public void tearDown() {
        vertx.close();
    }

    @Test
    public void shouldAuthenticateUserWithJwt(TestContext testContext) throws JOSEException {
        Async async = testContext.async();
        String state = UUID.randomUUID().toString();
        String nonce = Base64.getEncoder().encodeToString(new JsonObject().put(Constant.ORIGINAL_URL, "https://orignal.com?oauth2/authorize?client=1234").put(Constant.STATE, state).toBuffer().getBytes());
        QueryString queryString = new QueryString("state", state);
        queryString.add("id_token", generateIdToken(nonce));
        queryString.add("adapter_id", adapter.getId());
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/oidc-adapter")
                .handler(resp -> {
                    testContext.assertTrue(200 == resp.statusCode());
                    resp.bodyHandler(body -> {
                        testContext.assertEquals("https://orignal.com?oauth2/authorize?client=1234", body.toJsonObject().getString(Constant.ORIGINAL_URL));
                        async.complete();
                    });
                })
                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                .putHeader("Cookie", "guard_adapter_nonce=" + nonce)
                .putHeader("Content-Length", String.valueOf(Buffer.buffer(queryString.getQuery()).length()))
                .write(Buffer.buffer(queryString.getQuery()))
                .end();
    }

    @Test
    public void shouldRejectUserWhenStateIsNotValidWithJwt(TestContext testContext) throws JOSEException {
        Async async = testContext.async();
        String state = UUID.randomUUID().toString();
        String nonce = Base64.getEncoder().encodeToString(new JsonObject().put(Constant.ORIGINAL_URL, "https://orignal.com?oauth2/authorize?client=1234").put(Constant.STATE, state).toBuffer().getBytes());
        QueryString queryString = new QueryString("state", "1234");
        queryString.add("id_token", generateIdToken(nonce));
        queryString.add("adapter_id", adapter.getId());
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/oidc-adapter")
                .handler(resp -> {
                    testContext.assertTrue(401 == resp.statusCode());
                    async.complete();
                })
                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                .putHeader("Cookie", "guard_adapter_nonce=" + nonce)
                .putHeader("Content-Length", String.valueOf(Buffer.buffer(queryString.getQuery()).length()))
                .write(Buffer.buffer(queryString.getQuery()))
                .end();
    }

    @Test
    public void shouldAuthenticateUserWithJwe(TestContext testContext) throws JOSEException {
        Async async = testContext.async();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>();
        try {
            String state = UUID.randomUUID().toString();
            String nonce = Base64.getEncoder().encodeToString(new JsonObject().put(Constant.ORIGINAL_URL, "https://orignal.com?oauth2/authorize?client=1234").put(Constant.STATE, state).toBuffer().getBytes());
            String idToken = generateIdToken(nonce);
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_STRING));
            this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, new JsonObject().put(Constant.PAYLOAD, idToken), options.get(), r -> {
                QueryString queryString = new QueryString("state", state);
                queryString.add("id_token", ((JsonObject) r.result().body()).getString(Constant.RESPONSE));
                queryString.add("adapter_id", adapter.getId());
                vertx.createHttpClient(new HttpClientOptions()
                        .setSsl(true)
                        .setVerifyHost(false)
                        .setTrustAll(true))
                        .post(port, "localhost", "/auth/oidc-adapter")
                        .handler(resp -> {
                            testContext.assertTrue(200 == resp.statusCode());
                            resp.bodyHandler(body -> {
                                JsonObject response = body.toJsonObject();
                                testContext.assertEquals("https://orignal.com?oauth2/authorize?client=1234", response.getString(Constant.ORIGINAL_URL));
                                async.complete();
                            });

                        })
                        .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                        .putHeader("Cookie", "guard_adapter_nonce=" + nonce)
                        .putHeader("Content-Length", String.valueOf(Buffer.buffer(queryString.getQuery()).length()))
                        .write(Buffer.buffer(queryString.getQuery()))
                        .end();
            });
        } catch (JOSEException e) {
            testContext.fail(e);
        }
    }

    private String generateIdToken(String nonce) throws JOSEException {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.issuer("guard").subject("kad").claim(Constant.NONCE, nonce);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), builder.build());
        signedJWT.sign(new RSASSASigner(keyPair.getPrivate()));
        return signedJWT.serialize();
    }


}