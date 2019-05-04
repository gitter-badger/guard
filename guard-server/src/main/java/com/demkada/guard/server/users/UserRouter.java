package com.demkada.guard.server.users;

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

public class UserRouter {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserRouter.class);

    private final Router router;

    public UserRouter(Vertx vertx) {
        UserService userService = new UserService(vertx);

        router = Router.router(vertx);
        router.route().handler(new GuardAuditor(vertx, "User"));

        configRouterPaths(userService);
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(String.format("Guard user router %s is waiting for requests", this.toString().split("@")[1]));
        }
    }

    private void configRouterPaths(UserService userService) {
        router.get("/")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(userService::getUsers);

        router.get("/")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(userService::getUserByEmail);

        router.put("/")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(userService::updateUser);

        router.put("/password")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(userService::changePassword);

        router.post("/confirm-phone")
                .produces(Constant.CONTENT_TYPE_JSON)
                .consumes(Constant.CONTENT_TYPE_JSON)
                .handler(context -> {
                    //TODO Confirm Phone number Request by sending a SMS or making a phone call
                });

        router.get("/confirm-phone/:confirmationKey")
                .produces(Constant.CONTENT_TYPE_JSON)
                .handler(context -> {
                    //TODO Confirm Phone number by checking SMS answer or phone call answer
                });
    }

    public Router getRouter() {
        return router;
    }
}
