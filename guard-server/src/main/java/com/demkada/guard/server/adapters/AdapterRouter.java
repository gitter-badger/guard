package com.demkada.guard.server.adapters;

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
import com.demkada.guard.server.commons.utils.GuardAuditor;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AdapterRouter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AdapterRouter.class);

    private final Router router;

    public AdapterRouter(Vertx vertx) {
        AdapterService adapterService = new AdapterService(vertx);
        router = Router.router(vertx);
        router.route().handler(new GuardAuditor(vertx,"Adapter"));

        router.route("/*").handler(context -> {
            if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                context.next();
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end();
            }
        });

        configRouterPaths(adapterService);
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(String.format("Guard Adapters router %s is waiting for requests", this.toString().split("@")[1]));
        }

    }

    private void configRouterPaths(AdapterService adapterService) {

        router.post("/")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(adapterService::createAdapter);

        router.get("/")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(adapterService::getAdapters);

        router.get("/:id")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(adapterService::getAdapterById);

        router.put("/:id")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(adapterService::updateAdapter);

        router.delete("/:id")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(adapterService::deleteAdapter);
    }

    public Router getRouter() {
        return router;
    }
}
