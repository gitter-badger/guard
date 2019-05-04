package com.demkada.guard.server;

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
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.ManagerFactory_For_Guard;
import info.archinnov.achilles.junit.AchillesTestResource;
import info.archinnov.achilles.junit.AchillesTestResourceBuilder;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
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

@RunWith(VertxUnitRunner.class)
public class RouterTest {

    static {
        System.setProperty("vertx.disableDnsResolver", "true");
    }

    private Vertx vertx;
    private int port;

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

    @Before
    public void SetUp(TestContext testContext) throws IOException {
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
    public void shouldReturnOidcConfig(TestContext testContext) {
        Async async = testContext.async();
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/.well-known/openid-configuration")
                .handler(r -> {
                    testContext.assertEquals(200, r.statusCode());
                    r.bodyHandler(b -> {
                        testContext.assertEquals(b.toJsonObject().getString("issuer"), "https://localhost:" + port);
                        testContext.assertEquals(b.toJsonObject().getString("authorization_endpoint"), "https://localhost:" + port + "/oauth2/authorize");
                        testContext.assertEquals(b.toJsonObject().getString("token_endpoint"), "https://localhost:" + port + "/oauth2/token");
                        testContext.assertEquals(b.toJsonObject().getString("jwks_uri"), "https://localhost:" + port + "/oauth2/jwks.json");
                        testContext.assertEquals(b.toJsonObject().getJsonArray("response_types_supported"), new JsonArray().add("code").add("token").add("id_token"));
                        testContext.assertEquals(b.toJsonObject().getJsonArray("subject_types_supported"), new JsonArray().add("public"));
                        testContext.assertEquals(b.toJsonObject().getJsonArray("id_token_signing_alg_values_supported"), new JsonArray().add("RS256"));
                        async.complete();
                    });
                })
                .putHeader("Content-Type", "application/json")
                .end();
    }

}