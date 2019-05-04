package com.demkada.guard.server.scope;

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
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ScopeRouter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScopeRouter.class);

    private final Router router;

    public ScopeRouter(Vertx vertx) {
        ScopeService scopeService = new ScopeService(vertx);

        router = Router.router(vertx);
        router.route().handler(new GuardAuditor(vertx, "Scope"));

        configRouterPaths(scopeService);
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(String.format("Guard Scope router %s is waiting for requests", this.toString().split("@")[1]));
        }
    }

    private void configRouterPaths(ScopeService scopeService) {

        router.post("/")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(scopeService::createScope);

        router.get("/")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(scopeService::getScopes);

        router.get("/:" + Constant.NAME)
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(scopeService::getScopeByName);

        router.put("/:" + Constant.NAME)
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(scopeService::updateScope);

        router.delete("/:" + Constant.NAME)
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(scopeService::deleteScope);
    }

    public Router getRouter() {
        return router;
    }

}
