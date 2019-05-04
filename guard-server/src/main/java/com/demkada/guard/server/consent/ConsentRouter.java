package com.demkada.guard.server.consent;

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

public class ConsentRouter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConsentRouter.class);

    private final Router router;

    public ConsentRouter(Vertx vertx) {
        ConsentService consentService = new ConsentService(vertx);

        router = Router.router(vertx);
        router.route().handler(new GuardAuditor(vertx,"Consent"));

        configRouterPaths(consentService);
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(String.format("Guard Consent router %s is waiting for requests", this.toString().split("@")[1]));
        }
    }

    private void configRouterPaths(ConsentService consentService) {

        router.post("/")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(consentService::createConsents);

        router.get("/")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(consentService::getConsents);


        router.delete("/")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(consentService::deleteConsent);

    }

    public Router getRouter() {
        return router;
    }

}
