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


import com.demkada.guard.server.adapters.AdapterRouter;
import com.demkada.guard.server.auth.AuthRouter;
import com.demkada.guard.server.clients.ClientRouter;
import com.demkada.guard.server.commons.model.PrincipalType;
import com.demkada.guard.server.commons.model.GuardPrincipal;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardAuditor;
import com.demkada.guard.server.commons.utils.Utils;
import com.demkada.guard.server.consent.ConsentRouter;
import com.demkada.guard.server.oauth2.OAuth2Router;
import com.demkada.guard.server.scope.ScopeRouter;
import com.demkada.guard.server.users.UserRouter;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.handler.CorsHandler;
import io.vertx.ext.web.handler.StaticHandler;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public class Router {

    private final Vertx vertx;
    private io.vertx.ext.web.Router instance;

    Router(Vertx vertx) {
        this.vertx = vertx;
        instance = io.vertx.ext.web.Router.router(this.vertx);

        instance.route().handler(CookieHandler.create());
        instance.route().handler(BodyHandler.create());
        instance.get("/health")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(c -> c.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end());

        instance.get("/context")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(new GuardAuditor(vertx, "Context"))
                .handler(this::context);

        instance.get("/.well-known/openid-configuration")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(CorsHandler.create("*").allowedMethod(HttpMethod.GET).allowedHeader("Authorization"))
                .handler(new GuardAuditor(vertx, "guard-configuration"))
                .handler(this::oidcConfig);

        instance.mountSubRouter("/auth", new AuthRouter(vertx).getRouter());
        instance.mountSubRouter("/oauth2", new OAuth2Router(vertx).getRouter());

        instance.route("/api/*").handler(new AuthHandler(vertx)::handle);
        instance.mountSubRouter("/api/users", new UserRouter(vertx).getRouter());
        instance.mountSubRouter("/api/clients", new ClientRouter(vertx).getRouter());
        instance.mountSubRouter("/api/scopes", new ScopeRouter(vertx).getRouter());
        instance.mountSubRouter("/api/consents", new ConsentRouter(vertx).getRouter());
        instance.mountSubRouter("/api/adapters", new AdapterRouter(vertx).getRouter());

        instance.route("/oidc-adapter/*").handler(StaticHandler.create("oidc-adapter"));
        instance.route("/manager/*").handler(StaticHandler.create("webroot/manager"));
        instance.route("/apidoc/*").handler(new AuthHandler(vertx, true)::handle);
        instance.route("/apidoc/").handler(StaticHandler.create("apidoc/oauth2"));
        instance.route("/apidoc/oauth2/*").handler(StaticHandler.create("apidoc/oauth2"));
        instance.route("/*").handler(StaticHandler.create(vertx.getOrCreateContext().config().getString(Constant.GUARD_CUSTOM_AUTH_FRONTEND_PATH, "webroot/auth")));

        instance.route().failureHandler(new GuardAuditor(vertx, "Guard"));
    }

    private void oidcConfig(RoutingContext context) {
        JsonObject config = new JsonObject();
        String host = vertx.getOrCreateContext().config().getString(Constant.GUARD_SERVER_HOST, "https://" + context.request().host());
        config.put("issuer", vertx.getOrCreateContext().config().getString(Constant.GUARD_JWT_ISSUER, host));
        config.put("authorization_endpoint", host + "/oauth2/authorize");
        config.put("token_endpoint", host + "/oauth2/token");
        config.put("userinfo_endpoint", host + "/oauth2/userinfo");
        config.put("revocation_endpoint", host + "/oauth2/revoke");
        config.put("introspection_endpoint", host + "/oauth2/introspect");
        config.put("jwks_uri", host + "/oauth2/jwks.json");
        config.put("response_types_supported", new JsonArray().add("code").add("token").add("id_token"));
        config.put("response_modes_supported", new JsonArray().add("query").add("fragment"));
        config.put("grant_types_supported", new JsonArray().add("authorization_code").add("implicit"));
        config.put("subject_types_supported", new JsonArray().add("public"));
        config.put("acr_values_supported", new JsonArray().add("LOA1").add("LOA2").add("LOA3").add("LOA4"));
        config.put("id_token_signing_alg_values_supported", new JsonArray().add("RS256"));
        config.put("token_endpoint_auth_methods_supported", new JsonArray().add("client_secret_basic"));
        config.put("claim_types_supported", new JsonArray().add("normal"));

        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).end(config.encodePrettily());
    }

    public io.vertx.ext.web.Router getInstance() {
        return instance;
    }

    private void context(RoutingContext context) {
        JsonObject appContext = initAppContext();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_ADAPTERS));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject());
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries.get(), options.get(), res -> {
            if (res.succeeded()) {
                appContext.put("adapters", ((JsonObject) res.result().body()).getJsonArray(Constant.RESPONSE));
            }
            Future<JsonObject> userFuture = Future.future();
            getUser(context, options, entries, userFuture);
            userFuture.setHandler(ar -> {
                if (ar.succeeded()) {
                    appContext.put("user", ar.result());
                }
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).end(appContext.encode());
            });
        });
    }

    private void getUser(RoutingContext context, AtomicReference<DeliveryOptions> options, AtomicReference<JsonObject> entries, Future<JsonObject> userFuture) {
        Cookie cookieToken = context.getCookie(vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_NAME, Constant.GUARD));
        if(Objects.nonNull(cookieToken) && !cookieToken.getValue().isEmpty()) {
            options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN));
            entries.set(new JsonObject().put(Constant.PAYLOAD, cookieToken.getValue()));
            vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
                if (reply.succeeded()) {
                    JsonObject resp = (JsonObject) reply.result().body();
                    JsonObject principal = new GuardPrincipal(resp.getJsonObject(Constant.RESPONSE), PrincipalType.END_USER).principal();
                    if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), principal.getString(Constant.EMAIL))) {
                        principal.put("admin", true);
                    }
                    userFuture.complete(principal);
                }
                else {
                    userFuture.fail("Not an end user");
                }
            });
        }
        else {
            userFuture.fail("Not an end user");
        }
    }

    private JsonObject initAppContext() {
        JsonObject appContext = new JsonObject();
        JsonObject config = new JsonObject();
        config.put(Constant.DISABLE_INTERNAL_IDP, vertx.getOrCreateContext().config().getBoolean(Constant.GUARD_DISABLE_INTERNAL_IDP, false));


        appContext.put("config", config);
        appContext.put("version", vertx.getOrCreateContext().config().getString("guard.version"));
        return appContext;
    }
}
