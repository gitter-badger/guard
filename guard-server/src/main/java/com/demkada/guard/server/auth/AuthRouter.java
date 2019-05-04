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


import com.demkada.guard.server.commons.SecurityQuestion;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardAuditor;
import com.demkada.guard.server.commons.utils.Utils;
import com.demkada.guard.server.AuthHandler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

public class AuthRouter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthRouter.class);

    private final Register register;
    private final Router router;
    private final Login login;
    private final OIDCAdapter oidcAdapter;
    private final NativeAdapter nativeAdapter;
    private final ConfirmEmail confirmEmail;
    private final ResetPassword resetPassword;
    private final SecurityQuestion securityQuestions = new SecurityQuestion();
    private final AuthHandler authHandler;
    private final Logout logout;

    public AuthRouter(Vertx vertx) {
        router = Router.router(vertx);
        router.route().handler(new GuardAuditor(vertx, "Authentication"));
        login = new Login(vertx);
        logout = new Logout(vertx);
        confirmEmail = new ConfirmEmail(vertx);
        resetPassword = new ResetPassword(vertx);
        register = new Register(vertx, this.confirmEmail);
        oidcAdapter = new OIDCAdapter(vertx);
        nativeAdapter = new NativeAdapter(vertx);
        authHandler = new AuthHandler(vertx);
        if (!vertx.getOrCreateContext().config().getBoolean(Constant.GUARD_DISABLE_INTERNAL_IDP, false)) {
            configInternalIDPRouters();
        }
        configRouterPaths(vertx);
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(String.format("Guard Auth router %s is waiting for requests", this.toString().split("@")[1]));
        }
    }

    private void configRouterPaths(Vertx vertx) {

        router.get("/redirect-url")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(context -> {
                    if (Objects.nonNull(context.request().getParam(Constant.ADAPTER_ID)) && Objects.nonNull(context.request().getParam(Constant.ORIGINAL_URL))) {
                        context.put(Constant.ADAPTER_ID, context.request().getParam(Constant.ADAPTER_ID));
                        context.put(Constant.ORIGINAL_URL, context.request().getParam(Constant.ORIGINAL_URL));
                        Utils.redirectToLoginPage(vertx, context);
                    }
                    else {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end();
                    }
                });

        router.post("/oidc-adapter")
                .consumes(Constant.CONTENT_X_FORM_URLENCODED)
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(oidcAdapter::login);

        router.post("/native-adapter")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(authHandler::handle)
                .handler(nativeAdapter::login);
    }

    private void configInternalIDPRouters() {
        router.post("/sign-in")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(login::handle);

        router.post("/sign-out")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(logout::handle);

        router.post("/sign-up")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(register::handle);

        router.get("/security-questions")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(context -> {
                    JsonArray response = new JsonArray();
                    if ("fr".equals(context.preferredLanguage().tag())) {
                        securityQuestions.getFrenchQuestions().forEach((k, v) -> response.add(new JsonObject().put(k.name(), v)));
                    } else {
                        securityQuestions.getEnglishQuestions().forEach((k, v) -> response.add(new JsonObject().put(k.name(), v)));
                    }
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(response.encode());
                });

        router.post("/reset-password")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(resetPassword::handleRequest);

        router.get("/reset-password/:reset_key")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(resetPassword::handleAuthorization);

        router.post("/reset-password/:reset_key")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(resetPassword::handleResult);

        router.post("/confirm-email")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(confirmEmail::handleRequest);

        router.get("/confirm-email/:confirmation_key")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(confirmEmail::handleResult);
    }

    public Router getRouter() {
        return router;
    }
}
