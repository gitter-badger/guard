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



import com.nimbusds.jose.jwk.RSAKey;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardAuditor;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.CorsHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class OAuth2Router {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2Router.class);

    private final Router router;
    private final AuthHandler authHandler;
    private final AuthorizeService authorizeService;
    private final TokenService tokenService;
    private final IntrospectService introspectService;
    private final RevocationService revocationService;
    private final UserInfoService userInfoService;

    public OAuth2Router(Vertx vertx) {
        router = Router.router(vertx);
        router.route().handler(new GuardAuditor(vertx, "OAuth2"));
        authHandler = new AuthHandler(vertx);
        authorizeService = new AuthorizeService(vertx);
        tokenService = new TokenService(vertx);
        introspectService = new IntrospectService(vertx);
        revocationService = new RevocationService(vertx);
        userInfoService = new UserInfoService(vertx);
        configRouterPaths(vertx);
        router.get("/jwks.json")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(CorsHandler.create("*").allowedMethod(HttpMethod.GET).allowedHeader("Authorization"))
                .handler(context -> vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, new JsonObject(), new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_RSA_PUBLIC_KEY), res -> {
                    try {
                        String pubKey = Base64.getEncoder().encodeToString(((JsonObject)res.result().body()).getBinary(Constant.RESPONSE));
                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(pubKey));
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        String kid;
                        if (vertx.getOrCreateContext().config().containsKey(Constant.GUARD_KMIP_SERVER) && vertx.getOrCreateContext().config().getBoolean(Constant.GUARD_KMIP_SERVER)) {
                            kid = vertx.getOrCreateContext().config().getString(Constant.GUARD_KMIP_SERVER_RSA_PRIVATE_KEY);
                        } else {
                            kid = vertx.getOrCreateContext().config().getString(Constant.GUARD_CRYPTO_RSA_KEYPAIR_ALIAS, "guard-rsa-keypair");
                        }
                        RSAKey jwk = new RSAKey.Builder((RSAPublicKey) keyFactory.generatePublic(keySpec)).keyID(kid).build();
                        context.response().setStatusCode(200).putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).end(new JsonObject().put("keys", new JsonArray().add(jwk.toJSONObject())).encodePrettily());
                    } catch (Exception e) {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR_MESSAGE, "Internal error").encode());
                    }
                }));
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(String.format("Guard OAuth2 router %s is waiting for requests", this.toString().split("@")[1]));
        }
    }

    private void configRouterPaths(Vertx vertx) {

        router.get("/authorize")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(authHandler::checkOAuth2Client)
                .handler(authHandler::handleEndUserCookie)
                .handler(authorizeService::handle);

        Route tokenEndpoint = router.post("/token")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_X_FORM_URLENCODED);
        if (vertx.getOrCreateContext().config().getBoolean(Constant.GUARD_SERVER_ENABLE_CORS_ON_OAUHT2_TOKEN_ENDPOINT, false)) {
            tokenEndpoint.handler(CorsHandler.create("*").allowedMethod(HttpMethod.POST).allowedHeader("Authorization"));
        }
        tokenEndpoint
                .handler(authHandler::handleClientBasicAuthentication)
                .handler(tokenService::handle);

        router.get("/userinfo")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(CorsHandler.create("*").allowedMethod(HttpMethod.GET).allowedHeader("Authorization"))
                .handler(userInfoService::handle);

        router.post("/userinfo")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(CorsHandler.create("*").allowedMethod(HttpMethod.POST).allowedHeader("Authorization"))
                .handler(userInfoService::handle);

        router.post("/introspect")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_X_FORM_URLENCODED)
                .handler(authHandler::handleClientBasicAuthentication)
                .handler(introspectService::handle);

        router.post("/revoke")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_X_FORM_URLENCODED)
                .handler(authHandler::handleClientBasicAuthentication)
                .handler(revocationService::handle);

    }


    public Router getRouter() {
        return router;
    }
}
