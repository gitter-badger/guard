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
import java.util.Base64;
import java.util.Collections;

@RunWith(VertxUnitRunner.class)
public class NativeAdapterITCase {

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
    private int port;
    private Client client;

    @Before
    public void SetUp(TestContext testContext) throws Exception {
        Async async = testContext.async();
        Adapter adapter = new Adapter();
        adapter.setId("12345");
        adapter.setName("SAFE");
        adapter.setType(AdapterType.NATIVE);
        adapter.setDescription("SAFE Native adapter");
        adapter.setAdapterUrl("https://sas.com");
        resource.getManagerFactory().forAdapter().crud().insert(adapter).execute();

        client = new Client();
        client.setName("CloudCli");
        client.setId("client_CloudCli");
        client.setSecret("secret_CloudCli");
        client.setRedirectUris(Collections.singleton("https://localhost:8443"));
        client.setDescription("Created by CloudCli");

        Scope internalGenerateUserToken = new Scope();
        internalGenerateUserToken.setName(InternalScope.GUARD_GENERATE_USER_TOKEN.name());
        internalGenerateUserToken.setEnDescription("internalGenerateUserToken description");

        resource.getManagerFactory().forScope().crud().insert(internalGenerateUserToken).execute();

        ServerSocket serverSocket = new ServerSocket(0);
        port = serverSocket.getLocalPort();
        serverSocket.close();

        vertx = Vertx.vertx();

        StringHashUtil.generateHash(vertx, client.getSecret(), asyncResult -> {
            client.setSecret(asyncResult.result());
            resource.getManagerFactory().forClient().crud().insert(client).execute();
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

                    ), r -> {
                        if (r.succeeded()) {
                            async.complete();
                        }
                        else {
                            testContext.fail();
                        }
                    });
        });
    }

    @After
    public void tearDown() {
        vertx.close();
    }


    @Test
    public void shouldCreateUserToken(TestContext testContext) {
        Async async = testContext.async();
        QueryString body = new QueryString("grant_type", "client_credentials");
        body.add("scope", "GUARD_GENERATE_USER_TOKEN");
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/oauth2/token")
                .handler(tokenResult -> tokenResult.bodyHandler(b -> {
                    JsonObject payload = new JsonObject().put(Constant.SUB, "kad");
                    vertx.createHttpClient(new HttpClientOptions()
                            .setSsl(true)
                            .setVerifyHost(false)
                            .setTrustAll(true))
                            .post(port, "localhost", "/auth/native-adapter")
                            .handler(resp -> {
                                testContext.assertTrue(200 == resp.statusCode());
                                resp.bodyHandler(userTokenResult -> {
                                    testContext.assertTrue(userTokenResult.toJsonObject().containsKey("guard_cookie_name"));
                                    testContext.assertTrue(userTokenResult.toJsonObject().containsKey("guard_cookie_value"));
                                    testContext.assertTrue(userTokenResult.toJsonObject().containsKey("guard_cookie_domain"));
                                    async.complete();
                                });
                            })
                            .putHeader("Content-Type", Constant.CONTENT_TYPE_JSON)
                            .putHeader("Authorization", "Bearer " +   b.toJsonObject().getString("access_token"))
                            .putHeader("Content-Length", String.valueOf(payload.toBuffer().length()))
                            .write(payload.toBuffer())
                            .end();
                }))
                .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client.getId() + ":secret_CloudCli").getBytes()))
                .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                .write(Buffer.buffer(body.getQuery()))
                .end();
    }

}