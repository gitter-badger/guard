package com.demkada.guard.server.oauth2;

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
import com.icegreen.greenmail.util.ServerSetupTest;
import com.nimbusds.jwt.JWTParser;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.ManagerFactory_For_Guard;
import info.archinnov.achilles.junit.AchillesTestResource;
import info.archinnov.achilles.junit.AchillesTestResourceBuilder;
import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.apache.commons.lang3.StringUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(VertxUnitRunner.class)
public class OAuth2RouterITCase {

    static {
        System.setProperty("vertx.disableDnsResolver", "true");
    }

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


    @Test
    public void shouldRedirectToLoginPage(TestContext testContext) {
        Async async = testContext.async();
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/oauth2/authorize?response_type=code&client_id=" + client1.getId() + "&state=xyz")
                .handler(r -> {
                    testContext.assertEquals(302, r.statusCode());
                    testContext.assertTrue( r.getHeader("Location").startsWith("https://localhost:8443/#/auth/sign-in"));
                    testContext.assertTrue( r.getHeader("Location").contains("original_url"));
                    async.complete();
                })
                .putHeader("Content-Type", "application/json")
                .end();
    }

    @Test
    public void shouldGetJwkSet(TestContext testContext) {
        Async async = testContext.async();
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/oauth2/jwks.json")
                .handler(r -> {
                    testContext.assertEquals(200, r.statusCode());
                    r.bodyHandler(body -> {
                        testContext.assertNotNull(body.toJsonObject().getJsonArray("keys"));
                        async.complete();
                    });
                })
                .putHeader("Content-Type", "application/json")
                .end();
    }

    @Test
    public void shouldRedirectToNativeAdapter(TestContext testContext) {
        Adapter adapter = new Adapter();
        adapter.setId("12345");
        adapter.setType(AdapterType.NATIVE);
        adapter.setAdapterUrl("https://safe.com");
        adapter.setTriggerOnHostname("localhost");
        resource.getManagerFactory().forAdapter().crud().insert(adapter).execute();
        Async async = testContext.async();
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/oauth2/authorize?response_type=code&client_id=" + client1.getId() + "&state=xyz")
                .handler(r -> {
                    testContext.assertEquals(302, r.statusCode());
                    testContext.assertTrue( r.getHeader("Location").startsWith("https://safe.com?original_url"));
                    async.complete();
                })
                .putHeader("Content-Type", "application/json")
                .end();
    }

    @Test
    public void shouldRedirectToOIDCAdapter(TestContext testContext) {
        Adapter adapter = new Adapter();
        adapter.setId("12345");
        adapter.setType(AdapterType.OIDC);
        adapter.setClientId("ABCDE");
        adapter.setAdapterUrl("https://sas.com");
        adapter.setTriggerOnHostname("localhost");
        resource.getManagerFactory().forAdapter().crud().insert(adapter).execute();
        Async async = testContext.async();
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/oauth2/authorize?response_type=code&client_id="+ client1.getId() + "&state=xyz")
                .handler(r -> {
                    testContext.assertEquals(302, r.statusCode());
                    testContext.assertTrue( r.getHeader("Location").startsWith("https://sas.com?response_type=id_token"));
                    async.complete();
                })
                .putHeader("Content-Type", "application/json")
                .end();
    }

    @Test
    public void shouldRedirectToConsentPage(TestContext testContext) {
        Async async = testContext.async();
        QueryString queryString = new QueryString("client_id", client1.getId());
        queryString.add("response_type", "code");
        queryString.add("redirect_uri", client1.getRedirectUris().stream().findFirst().get());
        queryString.add("state", "12345");
        queryString.add("scope", "scope1 scope5 " + scope3.getName());
        loginUser(user, ar -> vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/oauth2/authorize?" + queryString.getQuery())
                .handler(r -> {
                    testContext.assertEquals(302, r.statusCode());
                    testContext.assertTrue( r.getHeader("Location").startsWith("https://localhost:8443/#/consent?"));
                    testContext.assertFalse( r.getHeader("Location").contains("to_be_consented=scope1"));
                    testContext.assertTrue( r.getHeader("Location").contains("consented=scope1"));
                    testContext.assertTrue( r.getHeader("Location").contains("to_be_consented=scope3"));
                    testContext.assertTrue( r.getHeader("Location").contains("mfa_required=scope3"));
                    testContext.assertFalse( r.getHeader("Location").contains("to_be_consented=scope5"));
                    testContext.assertTrue( r.getHeader("Location").contains("original_url"));
                    async.complete();
                })
                .putHeader("Cookie", ar.result())
                .putHeader("Content-Type", "application/json")
                .end());
    }

    @Test
    public void shouldHandleOAuth2ImplicitFlow(TestContext testContext) {
        Async async = testContext.async();
        QueryString queryString = new QueryString("client_id", client1.getId());
        queryString.add("response_type", "token");
        queryString.add("redirect_uri", client1.getRedirectUris().stream().findFirst().get());
        queryString.add("state", "12345");
        queryString.add("scope", "scope1");
        loginUser(user, ar -> vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/oauth2/authorize?" + queryString.getQuery())
                .handler(r -> {
                    testContext.assertEquals(302, r.statusCode());
                    testContext.assertNotNull(r.getHeader("Location"));
                    testContext.assertTrue(r.getHeader("Location").startsWith(client1.getRedirectUris().stream().findFirst().get() + "#"));
                    try {
                        URL url = new URL(r.getHeader("Location"));
                        Map<String, String> qs = new HashMap<>();
                        Arrays.asList(url.toURI().getFragment().split("&")).forEach(f -> {
                            String[] query = f.split("=");
                            qs.put(query[0], query[1]);
                        });
                        testContext.assertTrue(qs.containsKey("access_token"));
                        if (opaqueAccessToken) {
                            testContext.assertEquals(5, qs.get("access_token").split("\\.").length);
                        }
                        else {
                            testContext.assertEquals(3, qs.get("access_token").split("\\.").length);
                        }
                        testContext.assertEquals("Bearer", qs.get("token_type"));
                        testContext.assertEquals("12345", qs.get("state"));
                        testContext.assertEquals("3600", qs.get("expires_in"));
                        async.complete();
                    } catch (Exception e) {
                        testContext.fail(e);
                    }
                })
                .putHeader("Cookie", ar.result())
                .putHeader("Content-Type", "application/json")
                .end());
    }

    @Test
    public void shouldHandleOIDCImplicitFlow(TestContext testContext) {
        Async async = testContext.async();
        QueryString queryString = new QueryString("client_id", client1.getId());
        queryString.add("response_type", "id_token");
        queryString.add("redirect_uri", client1.getRedirectUris().stream().findFirst().get());
        queryString.add("state", "12345");
        queryString.add("scope", "openid");
        queryString.add("nonce", "xyz");
        loginUser(user, ar -> vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/oauth2/authorize?" + queryString.getQuery())
                .handler(r -> {
                    testContext.assertEquals(302, r.statusCode());
                    testContext.assertNotNull(r.getHeader("Location"));
                    testContext.assertTrue(r.getHeader("Location").startsWith(client1.getRedirectUris().stream().findFirst().get() + "#"));
                    try {
                        URL url = new URL(r.getHeader("Location"));
                        Map<String, String> qs = new HashMap<>();
                        Arrays.asList(url.toURI().getFragment().split("&")).forEach(f -> {
                            String[] query = f.split("=");
                            qs.put(query[0], query[1]);
                        });
                        testContext.assertTrue(qs.containsKey("id_token"));
                        testContext.assertEquals(3, qs.get("id_token").split("\\.").length);
                        testContext.assertNull(qs.get("token_type"));
                        testContext.assertEquals("12345", qs.get("state"));
                        testContext.assertEquals("3600", qs.get("expires_in"));
                        async.complete();
                    } catch (Exception e) {
                        testContext.fail(e);
                    }
                })
                .putHeader("Cookie", ar.result())
                .putHeader("Content-Type", "application/json")
                .end());
    }

    @Test
    public void shouldHandleOauth2AuthZCodeFlow(TestContext testContext) {
        Async async = testContext.async();
        QueryString queryString = new QueryString();
        queryString.add("client_id", client1.getId());
        queryString.add("response_type", "code");
        queryString.add("redirect_uri", client1.getRedirectUris().stream().findFirst().get());
        queryString.add("state", "12345");
        queryString.add("scope", "scope1 scope2 scope4");
        loginUser(user, ar -> vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/oauth2/authorize?" + queryString.getQuery())
                .handler(r -> {
                    testContext.assertEquals(302, r.statusCode());
                    testContext.assertNotNull(r.getHeader("Location"));
                    testContext.assertTrue(r.getHeader("Location").startsWith(client1.getRedirectUris().stream().findFirst().get()));
                    try {
                        Map<String, String> qs = new HashMap<>();
                        Arrays.asList(new URL(r.getHeader("Location")).getQuery().split("&")).forEach(f -> {
                            String[] query = f.split("=");
                            qs.put(query[0], query[1]);
                        });
                        testContext.assertTrue(qs.containsKey("code"));
                        testContext.assertFalse(qs.get("code").isEmpty());
                        testContext.assertEquals("12345", qs.get("state"));
                        QueryString body = new QueryString("grant_type", "authorization_code");
                        body.add("code", qs.get("code"));
                        body.add("redirect_uri", client1.getRedirectUris().stream().findFirst().get());
                        vertx.createHttpClient(new HttpClientOptions()
                                .setSsl(true)
                                .setVerifyHost(false)
                                .setTrustAll(true))
                                .post(port, "localhost", "/oauth2/token")
                                .handler(tokenResult -> {
                                    testContext.assertTrue(200 == tokenResult.statusCode());
                                    tokenResult.bodyHandler(b -> {
                                        testContext.assertNotNull(b.toJsonObject());
                                        testContext.assertTrue(b.toJsonObject().containsKey("access_token"));
                                        testContext.assertTrue(b.toJsonObject().containsKey("refresh_token"));
                                        testContext.assertEquals("Bearer", b.toJsonObject().getString("token_type"));
                                        testContext.assertEquals(900, b.toJsonObject().getInteger("expires_in"));
                                        if (opaqueAccessToken) {
                                            testContext.assertEquals(5, b.toJsonObject().getString("access_token").split("\\.").length);
                                        }
                                        else {
                                            testContext.assertEquals(3, b.toJsonObject().getString("access_token").split("\\.").length);
                                            try {
                                                testContext.assertTrue(JWTParser.parse(b.toJsonObject().getString("access_token")).getJWTClaimsSet().getStringListClaim("scope").contains("scope1"));
                                                testContext.assertEquals(StringUtils.stripEnd(Base64.getUrlEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(TestPKI.CERT.getBytes())).getEncoded())), "="),
                                                        JWTParser.parse(b.toJsonObject().getString("access_token")).getJWTClaimsSet().getJSONObjectClaim("cnf").getAsString("x5t#S256"));
                                            } catch (Exception e) {
                                                e.printStackTrace();
                                            }
                                        }
                                        QueryString qString = new QueryString("grant_type", "refresh_token");
                                        qString.add("refresh_token", b.toJsonObject().getString("refresh_token"));
                                        vertx.createHttpClient(new HttpClientOptions()
                                                .setSsl(true)
                                                .setVerifyHost(false)
                                                .setTrustAll(true))
                                                .post(port, "localhost", "/oauth2/token")
                                                .handler(refreshResult -> {
                                                    testContext.assertTrue(200 == refreshResult.statusCode());
                                                    refreshResult.bodyHandler(refreshBody -> {
                                                        testContext.assertNotNull(refreshBody.toJsonObject());
                                                        testContext.assertTrue(refreshBody.toJsonObject().containsKey("access_token"));
                                                        testContext.assertTrue(refreshBody.toJsonObject().containsKey("refresh_token"));
                                                        testContext.assertNotEquals(b.toJsonObject().getString("refresh_token"), refreshBody.toJsonObject().getString("refresh_token"));
                                                        if (opaqueAccessToken) {
                                                            testContext.assertEquals(5, refreshBody.toJsonObject().getString("access_token").split("\\.").length);
                                                        }
                                                        else {
                                                            testContext.assertEquals(3, refreshBody.toJsonObject().getString("access_token").split("\\.").length);
                                                            try {
                                                                testContext.assertFalse(JWTParser.parse(refreshBody.toJsonObject().getString("access_token")).getJWTClaimsSet().getStringListClaim("scope").contains("scope1"));
                                                            } catch (ParseException e) {
                                                                e.printStackTrace();
                                                            }
                                                        }
                                                        testContext.assertEquals("Bearer", refreshBody.toJsonObject().getString("token_type"));
                                                        testContext.assertEquals(900, refreshBody.toJsonObject().getInteger("expires_in"));
                                                        async.complete();
                                                    });
                                                })
                                                .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                                                .putHeader("Content-Length", String.valueOf(Buffer.buffer(qString.getQuery()).length()))
                                                .putHeader("client-cert", Base64.getEncoder().encodeToString((TestPKI.CERT).getBytes()))
                                                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                                                .write(Buffer.buffer(qString.getQuery()))
                                                .end();
                                    });
                                })
                                .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                                .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                                .putHeader("client-cert", Base64.getEncoder().encodeToString((TestPKI.CERT).getBytes()))
                                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                                .write(Buffer.buffer(body.getQuery()))
                                .end();
                    } catch (Exception e) {
                        testContext.fail(e);
                    }
                })
                .putHeader("Cookie", ar.result())
                .putHeader("Content-Type", "application/json")
                .end());
    }

    @Test
    public void shouldHandleUserInfoRequest(TestContext testContext) {
        Async async = testContext.async();
        QueryString queryString = new QueryString();
        queryString.add("response_type", "code");
        queryString.add("client_id", client1.getId());
        queryString.add("state", "12345");
        queryString.add("scope", "openid");
        queryString.add("redirect_uri", client1.getRedirectUris().stream().findFirst().get());
        queryString.add("nonce", "azerty");
        loginUser(user, ar -> vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/oauth2/authorize?" + queryString.getQuery())
                .handler(r -> {
                    try {
                        Map<String, String> qs = new HashMap<>();
                        Arrays.asList(new URL(r.getHeader("Location")).getQuery().split("&")).forEach(f -> {
                            String[] query = f.split("=");
                            qs.put(query[0], query[1]);
                        });
                        QueryString body = new QueryString("grant_type", "authorization_code");
                        body.add("code", qs.get("code"));
                        body.add("redirect_uri", client1.getRedirectUris().stream().findFirst().get());
                        vertx.createHttpClient(new HttpClientOptions()
                                .setSsl(true)
                                .setVerifyHost(false)
                                .setTrustAll(true))
                                .post(port, "localhost", "/oauth2/token")
                                .handler(tokenResult -> {
                                    tokenResult.bodyHandler(b -> {
                                        testContext.assertNotNull(b.toJsonObject());
                                        testContext.assertTrue(b.toJsonObject().containsKey("access_token"));
                                        vertx.createHttpClient(new HttpClientOptions()
                                                .setSsl(true)
                                                .setVerifyHost(false)
                                                .setTrustAll(true))
                                                .get(port, "localhost", "/oauth2/userinfo")
                                                .handler(userInfoHandler -> {
                                                    testContext.assertTrue(200 == userInfoHandler.statusCode());
                                                    userInfoHandler.bodyHandler(userInfo -> {
                                                        testContext.assertNotNull(userInfo.toJsonObject());
                                                        testContext.assertEquals(user.getSub(), userInfo.toJsonObject().getString("sub"));
                                                        testContext.assertEquals(user.getGivenName(), userInfo.toJsonObject().getString("given_name"));
                                                        testContext.assertEquals(user.getFamilyName(), userInfo.toJsonObject().getString("family_name"));
                                                        testContext.assertEquals(user.getEmail(), userInfo.toJsonObject().getString("email"));

                                                        async.complete();
                                                    });
                                                })
                                                .putHeader("Authorization", "Bearer " + b.toJsonObject().getString("access_token"))
                                                .end();
                                    });
                                })
                                .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                                .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                                .write(Buffer.buffer(body.getQuery()))
                                .end();
                    } catch (Exception e) {
                        testContext.fail(e);
                    }
                })
                .putHeader("Cookie", ar.result())
                .putHeader("Content-Type", "application/json")
                .end());
    }

    @Test
    public void shouldHandleOIDC2AuthZCodeFlow(TestContext testContext) {
        Async async = testContext.async();
        QueryString queryString = new QueryString();
        queryString.add("client_id", client1.getId());
        queryString.add("response_type", "code");
        queryString.add("redirect_uri", client1.getRedirectUris().stream().findFirst().get());
        queryString.add("state", "12345");
        queryString.add("scope", "openid");
        queryString.add("nonce", "azerty");
        loginUser(user, ar -> vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/oauth2/authorize?" + queryString.getQuery())
                .handler(r -> {
                    testContext.assertEquals(302, r.statusCode());
                    try {
                        Map<String, String> qs = new HashMap<>();
                        Arrays.asList(new URL(r.getHeader("Location")).getQuery().split("&")).forEach(f -> {
                            String[] query = f.split("=");
                            qs.put(query[0], query[1]);
                        });
                        testContext.assertTrue(qs.containsKey("code"));
                        testContext.assertFalse(qs.get("code").isEmpty());
                        QueryString body = new QueryString("grant_type", "authorization_code");
                        body.add("code", qs.get("code"));
                        body.add("redirect_uri", client1.getRedirectUris().stream().findFirst().get());
                        vertx.createHttpClient(new HttpClientOptions()
                                .setSsl(true)
                                .setVerifyHost(false)
                                .setTrustAll(true))
                                .post(port, "localhost", "/oauth2/token")
                                .handler(tokenResult -> {
                                    testContext.assertTrue(200 == tokenResult.statusCode());
                                    tokenResult.bodyHandler(b -> {
                                        testContext.assertNotNull(b.toJsonObject());
                                        testContext.assertTrue(b.toJsonObject().containsKey("access_token"));
                                        testContext.assertTrue(b.toJsonObject().containsKey("id_token"));
                                        testContext.assertTrue(b.toJsonObject().containsKey("refresh_token"));
                                        testContext.assertEquals("Bearer", b.toJsonObject().getString("token_type"));
                                        testContext.assertEquals(900, b.toJsonObject().getInteger("expires_in"));
                                        if (opaqueAccessToken) {
                                            testContext.assertEquals(5, b.toJsonObject().getString("access_token").split("\\.").length);testContext.assertEquals(5, b.toJsonObject().getString("access_token").split("\\.").length);
                                        }
                                        else {
                                            testContext.assertEquals(3, b.toJsonObject().getString("access_token").split("\\.").length);
                                        }
                                        QueryString qString = new QueryString("grant_type", "refresh_token");
                                        qString.add("refresh_token", b.toJsonObject().getString("refresh_token"));
                                        vertx.createHttpClient(new HttpClientOptions()
                                                .setSsl(true)
                                                .setVerifyHost(false)
                                                .setTrustAll(true))
                                                .post(port, "localhost", "/oauth2/token")
                                                .handler(refreshResult -> {
                                                    testContext.assertTrue(200 == refreshResult.statusCode());
                                                    refreshResult.bodyHandler(refreshBody -> {
                                                        testContext.assertNotNull(refreshBody.toJsonObject());
                                                        testContext.assertTrue(refreshBody.toJsonObject().containsKey("access_token"));
                                                        testContext.assertFalse(refreshBody.toJsonObject().containsKey("id_token"));
                                                        testContext.assertTrue(refreshBody.toJsonObject().containsKey("refresh_token"));
                                                        testContext.assertNotEquals(b.toJsonObject().getString("refresh_token"), refreshBody.toJsonObject().getString("refresh_token"));
                                                        if (opaqueAccessToken) {
                                                            testContext.assertEquals(5, refreshBody.toJsonObject().getString("access_token").split("\\.").length);
                                                        }
                                                        else {
                                                            testContext.assertEquals(3, refreshBody.toJsonObject().getString("access_token").split("\\.").length);
                                                        }
                                                        testContext.assertEquals("Bearer", refreshBody.toJsonObject().getString("token_type"));
                                                        testContext.assertEquals(900, refreshBody.toJsonObject().getInteger("expires_in"));
                                                        async.complete();
                                                    });
                                                })
                                                .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                                                .putHeader("Content-Length", String.valueOf(Buffer.buffer(qString.getQuery()).length()))
                                                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                                                .write(Buffer.buffer(qString.getQuery()))
                                                .end();
                                    });
                                })
                                .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                                .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                                .write(Buffer.buffer(body.getQuery()))
                                .end();
                    } catch (Exception e) {
                        testContext.fail(e);
                    }
                })
                .putHeader("Cookie", ar.result())
                .putHeader("Content-Type", "application/json")
                .end());
    }

    @Test
    public void shouldHandleClientCredFlow(TestContext testContext) {
        Async async = testContext.async();
        QueryString body = new QueryString("grant_type", "client_credentials");
        body.add("scope", "scope4");
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/oauth2/token")
                .handler(tokenResult -> {
                    testContext.assertTrue(200 == tokenResult.statusCode());
                    tokenResult.bodyHandler(b -> {
                        testContext.assertNotNull(b.toJsonObject());
                        testContext.assertTrue(b.toJsonObject().containsKey("access_token"));
                        testContext.assertEquals("Bearer", b.toJsonObject().getString("token_type"));
                        testContext.assertEquals(3600, b.toJsonObject().getInteger("expires_in"));
                        if (opaqueAccessToken) {
                            testContext.assertEquals(5, b.toJsonObject().getString("access_token").split("\\.").length);
                        }
                        else {
                            testContext.assertEquals(3, b.toJsonObject().getString("access_token").split("\\.").length);
                        }
                        async.complete();
                    });
                })
                .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                .putHeader("client-cert", Base64.getEncoder().encodeToString((TestPKI.CERT).getBytes()))
                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                .write(Buffer.buffer(body.getQuery()))
                .end();
    }

    @Test
    public void shouldIntrospectJwtToken(TestContext testContext) {
        Async async = testContext.async();
        QueryString body = new QueryString("grant_type", "client_credentials");
        body.add("scope", "scope1 scope2");
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/oauth2/token")
                .handler(tokenResult -> tokenResult.bodyHandler(b -> {
                    String token = new QueryString("token", b.toJsonObject().getString("access_token")).getQuery();
                    vertx.createHttpClient(new HttpClientOptions()
                            .setSsl(true)
                            .setVerifyHost(false)
                            .setTrustAll(true))
                            .post(port, "localhost", "/oauth2/introspect")
                            .handler(introspectResult -> introspectResult.bodyHandler(i -> {
                                testContext.assertEquals(client1.getId(), i.toJsonObject().getString("sub"));
                                testContext.assertEquals("scope1 scope2", i.toJsonObject().getString("scope"));
                                async.complete();
                            }))
                            .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                            .putHeader("Content-Length", String.valueOf(Buffer.buffer(token).length()))
                            .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                            .write(Buffer.buffer(token))
                            .end();
                }))
                .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                .write(Buffer.buffer(body.getQuery()))
                .end();
    }

    @Test
    public void shouldRevokeRefreshToken(TestContext testContext) {
        Async async = testContext.async();
        QueryString queryString = new QueryString();
        queryString.add("client_id", client1.getId());
        queryString.add("response_type", "code");
        queryString.add("redirect_uri", client1.getRedirectUris().stream().findFirst().get());
        queryString.add("state", "12345");
        queryString.add("scope", "openid");
        queryString.add("nonce", "azerty");
        loginUser(user, ar -> vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .get(port, "localhost", "/oauth2/authorize?" + queryString.getQuery())
                .handler(r -> {
                    try {
                        testContext.assertEquals(302, r.statusCode());
                        Map<String, String> qs = new HashMap<>();
                        Arrays.asList(new URL(r.getHeader("Location")).getQuery().split("&")).forEach(f -> {
                            String[] query = f.split("=");
                            qs.put(query[0], query[1]);
                        });
                        testContext.assertTrue(qs.containsKey("code"));
                        testContext.assertFalse(qs.get("code").isEmpty());
                        QueryString body = new QueryString("grant_type", "authorization_code");
                        body.add("code", qs.get("code"));
                        body.add("redirect_uri", client1.getRedirectUris().stream().findFirst().get());
                        vertx.createHttpClient(new HttpClientOptions()
                                .setSsl(true)
                                .setVerifyHost(false)
                                .setTrustAll(true))
                                .post(port, "localhost", "/oauth2/token")
                                .handler(tokenResult -> {
                                    testContext.assertTrue(200 == tokenResult.statusCode());
                                    tokenResult.bodyHandler(b -> {
                                        String token = new QueryString("token", b.toJsonObject().getString("refresh_token")).getQuery();
                                        testContext.assertEquals(client1.getId(), resource.getManagerFactory().forRefreshToken().crud().findById(b.toJsonObject().getString("refresh_token"), client1.getId()).get().getClientId());
                                        vertx.createHttpClient(new HttpClientOptions()
                                                .setSsl(true)
                                                .setVerifyHost(false)
                                                .setTrustAll(true))
                                                .post(port, "localhost", "/oauth2/revoke")
                                                .handler(revokeResult -> {
                                                    testContext.assertEquals(200, revokeResult.statusCode());
                                                    testContext.assertNull(resource.getManagerFactory().forRefreshToken().crud().findById(b.toJsonObject().getString("refresh_token"), client1.getId()).get());
                                                    async.complete();
                                                })
                                                .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                                                .putHeader("Content-Length", String.valueOf(Buffer.buffer(token).length()))
                                                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                                                .write(Buffer.buffer(token))
                                                .end();

                                    });
                                })
                                .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((client1.getId() + ":secret_CloudCli").getBytes()))
                                .putHeader("Content-Length", String.valueOf(Buffer.buffer(body.getQuery()).length()))
                                .putHeader("Content-Type", Constant.CONTENT_X_FORM_URLENCODED)
                                .write(Buffer.buffer(body.getQuery()))
                                .end();
                    } catch (Exception e) {
                        testContext.fail(e);
                    }
                })
                .putHeader("Cookie", ar.result())
                .putHeader("Content-Type", "application/json")
                .end());
    }

    private void loginUser(User user, Handler<AsyncResult<String>> handler) {
        Future<String> future = Future.future();
        JsonObject b = new JsonObject().put("email", user.getEmail()).put("pwd", user.getPwd());
        vertx.createHttpClient(new HttpClientOptions()
                .setSsl(true)
                .setVerifyHost(false)
                .setTrustAll(true))
                .post(port, "localhost", "/auth/sign-in")
                .handler(r -> future.complete(r.getHeader("Set-Cookie")))
                .putHeader("Content-Type", "application/json")
                .putHeader("Content-Length", String.valueOf(b.toString().length()))
                .write(b.toBuffer())
                .end();
        future.setHandler(handler);
    }


    private Vertx vertx;
    private User user;
    private int port;
    private Client client1;
    private Client client2;
    private Scope scope1;
    private Scope scope2;
    private Scope scope3;
    private Scope scope4;
    private Scope scope5;
    private Consent consent1;
    private Consent consent2;
    private Consent consent3;
    private boolean opaqueAccessToken = false;


    @Before
    public void SetUp(TestContext testContext) throws IOException {
        user = new User();
        user.setEmail("kad.d@demkada.com");
        user.setEmailVerified(true);
        user.setSub("12345");
        user.setIdOrigin(Constant.GUARD);
        user.setPwd("toto");
        user.setAddress("Paris");
        user.setPhoneNumber("0000");
        user.setGivenName("Kad");
        user.setFamilyName("D.");
        Map<QuestionId, String> secQ = new HashMap<>();
        secQ.put(QuestionId.CHILDHOOD_FRIEND, "Mon meilleur ami d'enfance");
        secQ.put(QuestionId.PRIMARY_SCHOOL, "Tu te souviens bien");
        user.setSecurityQuestion(secQ);
        user.setPin("123456");

        client1 = new Client();
        client1.setName("CloudCli");
        client1.setId("client_CloudCli");
        client1.setSecret("secret_CloudCli");
        client1.setCertSubjectDn("CN=Guard");
        client1.setRedirectUris(Collections.singleton("https://localhost:8443"));
        client1.setDescription("Created by CloudCli");

        consent1 = new Consent();
        consent1.setScopeName("scope1");
        consent1.setClientId(client1.getId());
        consent1.setUserEmail(user.getEmail());
        consent1.setTimestamp(new Date());

        consent2 = new Consent();
        consent2.setScopeName("scope2");
        consent2.setClientId(client1.getId());
        consent2.setUserEmail(user.getEmail());
        consent2.setTimestamp(new Date());

        consent3 = new Consent();
        consent3.setScopeName("scope4");
        consent3.setClientId(client1.getId());
        consent3.setUserEmail(user.getEmail());
        consent3.setTimestamp(new Date());

        client2 = new Client();
        client2.setName("Guard client");
        client2.setId("client_guard");
        client2.setDescription("created by Guard");
        client2.setManagers(Collections.singleton("kadary.dembele@demkada.com"));

        scope1 = new Scope();
        scope1.setName("scope1");
        scope1.setEnDescription("Scope 1 description");
        scope1.setConsentTTL(360);
        scope1.setOneShot(true);
        scope1.setRefreshTokenTTL(720);

        scope2 = new Scope();
        scope2.setName("scope2");
        scope2.setEnDescription("Scope 2 description");
        scope2.setRestricted(true);
        scope2.setClientIdList(Collections.singleton(client1.getId()));
        scope2.setConsentTTL(360);
        scope2.setRefreshTokenTTL(720);

        scope3 = new Scope();
        scope3.setName("scope3");
        scope3.setEnDescription("Scope 3 description");
        scope3.setEndUserMFA(true);
        scope3.setMachineMFA(true);
        scope3.setConsentTTL(360);
        scope3.setRefreshTokenTTL(720);

        scope4 = new Scope();
        scope4.setName("scope4");
        scope4.setEnDescription("Scope 4 description");
        scope4.setMachineMFA(true);
        scope4.setConsentTTL(360);
        scope4.setAuthorizedFlows(Collections.singleton(GrantType.client_credentials));
        scope4.setRefreshTokenTTL(720);
        scope4.setTrustCaChain(TestPKI.INTERMEDIATE_CA + "\n" + TestPKI.ROOT_CA);

        scope5 = new Scope();
        scope5.setName("scope5");
        scope5.setEnDescription("Scope 5 description");
        scope5.setClientIdListForImplicitConsent(Collections.singleton(client1.getId()));
        scope5.setConsentTTL(360);
        scope4.setRefreshTokenTTL(720);

        ServerSocket serverSocket = new ServerSocket(0);
        port = serverSocket.getLocalPort();
        serverSocket.close();

        Async async = testContext.async();
        vertx = Vertx.vertx();
        vertx.deployVerticle(
                Guard.class.getName(),
                new DeploymentOptions().setConfig(
                        new JsonObject()
                                .put(Constant.GUARD_OAUTH2_OPAQUE_ACCESS_TOKEN, opaqueAccessToken)
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
                                .put(Constant.GUARD_CLIENT_CERT_HEADER, "client-cert")

                ),
                ar -> {
                    if (ar.succeeded()) {
                        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_USER_MODEL_PII));
                        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, new JsonArray().add(JsonObject.mapFrom(user))));
                        vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                            if (reply.succeeded()) {
                                User user  = ((JsonObject) reply.result().body()).getJsonArray(Constant.RESPONSE).getJsonObject(0).mapTo(User.class);
                                StringHashUtil.generateHash(vertx, user.getPwd(), hashResult -> {
                                    if (hashResult.succeeded()) {
                                        vertx.executeBlocking(future -> {
                                            user.setPwd(hashResult.result());
                                            consent1.setUserEmail(user.getEmail());
                                            consent2.setUserEmail(user.getEmail());
                                            consent3.setUserEmail(user.getEmail());
                                            resource.getManagerFactory().forUser().crud().insert(user).execute();
                                            resource.getManagerFactory().forScope().crud().insert(scope1).execute();
                                            scope1.setName("openid");
                                            scope1.setOneShot(false);
                                            resource.getManagerFactory().forScope().crud().insert(scope1).execute();
                                            resource.getManagerFactory().forScope().crud().insert(scope2).execute();
                                            resource.getManagerFactory().forScope().crud().insert(scope3).execute();
                                            resource.getManagerFactory().forScope().crud().insert(scope4).execute();
                                            resource.getManagerFactory().forScope().crud().insert(scope5).execute();
                                            resource.getManagerFactory().forConsent().crud().insert(consent1).execute();
                                            resource.getManagerFactory().forConsent().crud().insert(consent2).execute();
                                            resource.getManagerFactory().forConsent().crud().insert(consent3).execute();
                                            consent1.setScopeName("openid");
                                            resource.getManagerFactory().forConsent().crud().insert(consent1).execute();
                                            StringHashUtil.generateHash(vertx, client1.getSecret(), asyncResult -> {
                                                client1.setSecret(asyncResult.result());
                                                resource.getManagerFactory().forClient().crud().insert(client1).execute();
                                                future.complete();
                                            });
                                        }, r -> {
                                            if (r.succeeded()) {
                                                async.complete();
                                            }
                                            else {
                                                testContext.fail(r.cause());
                                            }
                                        });
                                    }
                                    else {
                                        testContext.fail(hashResult.cause());
                                    }
                                });
                            }
                            else {
                                testContext.fail(reply.cause());
                            }
                        });
                    }
                });
    }

    @After
    public void tearDown() {
        vertx.close();
    }




}