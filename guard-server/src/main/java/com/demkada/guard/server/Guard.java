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


import com.demkada.guard.server.adapters.AdapterManager;
import com.demkada.guard.server.clients.ClientManager;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.consent.ConsentManager;
import com.demkada.guard.server.crypto.CryptoManager;
import com.demkada.guard.server.mail.MailManager;
import com.demkada.guard.server.scope.ScopeManager;
import com.demkada.guard.server.users.UserManager;
import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.config.spi.utils.JsonObjectHelper;
import io.vertx.core.*;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Objects;
import java.util.Properties;

public class Guard extends AbstractVerticle {

    private static final Logger LOGGER = LoggerFactory.getLogger(Guard.class);

    @Override
    public void start(Future<Void> startFuture) {
        geConfig(configResponse -> {
            Future<String> steps = Future.future();
            steps.setHandler(stepsHandler -> {
                if (stepsHandler.succeeded()) {
                    LOGGER.info("Guard server is up and running...");
                    startFuture.complete();
                }
                else {
                    LOGGER.error("Unable to start Server", stepsHandler.cause());
                    startFuture.fail(stepsHandler.cause());
                }
            });

            Future<String> step1 = Future.future();
            vertx.deployVerticle(new MailManager(),
                    new DeploymentOptions()
                            .setConfig(configResponse.result()),
                    step1.completer());

            step1.compose(v -> {

                Future<String> step2 = Future.future();
                vertx.deployVerticle(CryptoManager.class.getName(),
                        new DeploymentOptions()
                                .setInstances(configResponse.result().getInteger(Constant.GUARD_CRYPTO_INSTANCES, 4))
                                .setConfig(configResponse.result()),
                        step2.completer());
                return step2;

            }).compose(v -> {

                Future<String> step3 = Future.future();
                vertx.deployVerticle(UserManager.class.getName(),
                        new DeploymentOptions()
                                .setInstances(configResponse.result().getInteger(Constant.GUARD_USERS_INSTANCES, 4))
                                .setConfig(configResponse.result()),
                        step3.completer());
                return step3;

            }).compose(v -> {

                Future<String> step4 = Future.future();
                vertx.deployVerticle(ClientManager.class.getName(),
                        new DeploymentOptions()
                                .setInstances(configResponse.result().getInteger(Constant.GUARD_CLIENTS_INSTANCES, 4))
                                .setConfig(configResponse.result()),
                        step4.completer());
                return step4;

            }).compose(v -> {

                Future<String> step5 = Future.future();
                vertx.deployVerticle(ScopeManager.class.getName(),
                        new DeploymentOptions()
                                .setInstances(configResponse.result().getInteger(Constant.GUARD_SCOPE_INSTANCES, 3))
                                .setConfig(configResponse.result()),
                        step5.completer());
                return step5;

            }).compose(v -> {

                Future<String> step6 = Future.future();
                vertx.deployVerticle(ConsentManager.class.getName(),
                        new DeploymentOptions()
                                .setInstances(configResponse.result().getInteger(Constant.GUARD_CONSENT_INSTANCES, 4))
                                .setConfig(configResponse.result()),
                        step6.completer());
                return step6;

            }).compose(v -> {

                Future<String> step7 = Future.future();
                vertx.deployVerticle(AdapterManager.class.getName(),
                        new DeploymentOptions()
                                .setInstances(configResponse.result().getInteger(Constant.GUARD_ADAPTER_INSTANCES, 4))
                                .setConfig(configResponse.result()),
                        step7.completer());
                return step7;

            }).compose(v -> vertx.deployVerticle(HttpServer.class.getName(),
                    new DeploymentOptions()
                            .setInstances(configResponse.result().getInteger(Constant.GUARD_HTTP_INSTANCES, 5))
                            .setConfig(configResponse.result()),
                    steps.completer()), steps);
        });
    }

    private void geConfig(Handler<AsyncResult<JsonObject>> handler) {
        Future<JsonObject> future = Future.future();
        future.setHandler(handler);
        final String vaultHost = System.getProperty(Constant.GUARD_VAULT_HOST_CONFIG_KEY, System.getenv(Constant.GUARD_VAULT_HOST_ENV_CONFIG_KEY));
        if (Objects.isNull(vaultHost) || vaultHost.isEmpty()) {
            future.complete(getDefaultConfig());
        }
        else {
            getConfigFromVault(future, vaultHost);
        }
    }

    private void getConfigFromVault(Future<JsonObject> future, String vaultHost) {
        final int vaultPort = Objects.nonNull(System.getProperty(Constant.GUARD_VAULT_PORT_CONFIG_KEY, System.getenv(Constant.GUARD_VAULT_PORT_ENV_CONFIG_KEY))) ? Integer.parseInt(System.getProperty(Constant.GUARD_VAULT_PORT_CONFIG_KEY, System.getenv(Constant.GUARD_VAULT_PORT_ENV_CONFIG_KEY))) : 8200;
        WebClient client = WebClient.create(vertx, new WebClientOptions()
                .setUserAgent("guard-server")
                .setKeepAlive(false));
        client.get(80, "169.254.169.254", "/latest/dynamic/instance-identity/pkcs7").send(ar -> {
            if (ar.succeeded()) {
                String guardVaultRole = Objects.nonNull(System.getProperty(Constant.GUARD_VAULT_ROLE_CONFIG_KEY, System.getenv(Constant.GUARD_VAULT_ROLE_ENV_CONFIG_KEY))) ? System.getProperty(Constant.GUARD_VAULT_ROLE_CONFIG_KEY, System.getenv(Constant.GUARD_VAULT_ROLE_ENV_CONFIG_KEY)) : "guard-ec2-role";
                final JsonObject entries = new JsonObject().put("role", guardVaultRole).put("pkcs7", ar.result().bodyAsString()).put("nonce", Constant.GUARD);
                getDataFromVault(future, vaultHost, vaultPort, client, entries);
            } else {
                LOGGER.error("Unable to get EC2 instance PKCS7 certificate for guard-vault init", ar.cause());
                future.fail(ar.cause());
            }
        });
    }

    private void getDataFromVault(Future<JsonObject> future, String vaultHost, int vaultPort, WebClient client, JsonObject entries) {
        client.post(vaultPort, vaultHost, "/v1/auth/aws/login")
                .ssl(Boolean.valueOf(System.getProperty(Constant.GUARD_VAULT_SSL_CONFIG_KEY, System.getenv(Constant.GUARD_VAULT_SSL_ENV_CONFIG_KEY))))
                .sendJsonObject(entries, tokenResponse -> {
                    if (tokenResponse.succeeded()) {
                        ConfigStoreOptions vaultStore = new ConfigStoreOptions()
                                .setType("vault")
                                .setConfig(new JsonObject()
                                        .put("host", vaultHost)
                                        .put("port", vaultPort)
                                        .put("ssl", Boolean.valueOf(System.getProperty(Constant.GUARD_VAULT_SSL_CONFIG_KEY, System.getenv(Constant.GUARD_VAULT_SSL_ENV_CONFIG_KEY))))
                                        .put("path", Objects.nonNull(System.getProperty(Constant.GUARD_VAULT_PATH_CONFIG_KEY, System.getenv(Constant.GUARD_VAULT_PATH_ENV_CONFIG_KEY))) ? System.getProperty(Constant.GUARD_VAULT_PATH_CONFIG_KEY, System.getenv(Constant.GUARD_VAULT_PATH_ENV_CONFIG_KEY)) : "secret/guard")
                                        .put("token", tokenResponse.result().bodyAsJsonObject().getJsonObject("auth").getString("client_token")));

                        ConfigRetriever.create(vertx, new ConfigRetrieverOptions()
                                .setScanPeriod(900000)
                                .addStore(vaultStore)).getConfig(vc -> {
                            if (vc.succeeded()) {
                                JsonObject config = getDefaultConfig();
                                vc.result().getMap().forEach((key, value) -> JsonObjectHelper.put(config, key, String.valueOf(value), false));
                                future.complete(config);
                            }
                            else {
                                future.complete(getDefaultConfig());
                            }
                        });
                    }
                    else {
                        LOGGER.error("Unable to get vault token for EC2 instance. Http status code:" + tokenResponse.result().statusCode(), tokenResponse.cause());
                        future.fail(tokenResponse.cause());
                    }
                });
    }

    private JsonObject getDefaultConfig() {
        JsonObject defaultConfig = vertx.getOrCreateContext().config();
        System.getProperties()
                .stringPropertyNames()
                .forEach(name -> JsonObjectHelper.put(defaultConfig, name, System.getProperties().getProperty(name), false));
        System.getenv().forEach((key, value) -> JsonObjectHelper.put(defaultConfig, key, value, false));
        JsonObject propConfig = new JsonObject();
        try {
            Properties properties = new Properties();
            properties.load(vertx.getClass().getClassLoader().getResourceAsStream("guard.properties"));
            propConfig = JsonObjectHelper.from(properties, false);
        } catch (IOException e) {
            LOGGER.error("unable to load guard.properties ", e);
        }
        return defaultConfig.mergeIn(propConfig);
    }
}