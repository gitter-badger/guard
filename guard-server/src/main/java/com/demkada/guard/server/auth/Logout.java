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


import com.demkada.guard.server.commons.utils.Constant;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.RoutingContext;

public class Logout {
    private final Vertx vertx;

    Logout(Vertx vertx) {
        this.vertx = vertx;
    }

    void handle(RoutingContext context) {
        Cookie cookie = Cookie.cookie(vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_NAME, Constant.GUARD), "");
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setMaxAge(0);
        cookie.setDomain(vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_DOMAIN, context.request().host().split(":")[0]));
        context.addCookie(cookie);
        context.response().setStatusCode(200).end();
    }
}
