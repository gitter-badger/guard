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


import com.demkada.guard.server.commons.utils.CassandraDriver;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.Utils;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.manager.RefreshToken_Manager;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

class RevocationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(RevocationService.class);

    private final Vertx vertx;
    private final RefreshToken_Manager refreshTokenManager;

    RevocationService(Vertx vertx) {
        this.vertx = vertx;
        refreshTokenManager = ManagerFactoryBuilder_For_Guard
                .builder(CassandraDriver.getOrCreate(vertx.getOrCreateContext().config()).getCluster())
                .withDefaultKeyspaceName(Constant.GUARD)
                .doForceSchemaCreation(false)
                .build()
                .forRefreshToken();
    }

    void handle(RoutingContext context) {
        String input = context.getBodyAsString();
        if (Objects.nonNull(input)) {
            String token = Utils.convertUrlFormEncodedToJsonObject(input).getString("token");
            if (Objects.nonNull(token)) {
                vertx.executeBlocking(f -> {
                    try {
                        refreshTokenManager.crud().deleteById(token, context.user().principal().getString(Constant.CLIENT_ID)).ifExists().execute();
                        f.complete();
                    }
                    catch (Exception e) {
                        f.fail(e);
                    }
                }, r -> {
                    if (r.succeeded()) {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
                    }
                    else {
                        LOGGER.debug("Revoking an expired refresh_token by clientID s" + context.user().principal().getString(Constant.CLIENT_ID), new GuardException(r.cause()));
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
                    }

                });
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "invalid_request").encode());
            }
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "invalid_request").encode());
        }
    }
}
