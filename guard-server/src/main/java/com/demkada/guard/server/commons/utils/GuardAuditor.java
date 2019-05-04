package com.demkada.guard.server.commons.utils;

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


import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.Objects;

public class GuardAuditor implements Handler<RoutingContext> {

    private final Vertx vertx;
    private String className;
    private static final Logger LOGGER = LoggerFactory.getLogger(GuardAuditor.class);

    public GuardAuditor(Vertx vertx, String className) {
        this.vertx = vertx;
        this.className = className;
    }

    @Override
    public void handle(RoutingContext context) {
        context.addBodyEndHandler(v -> {
            JsonObject event = buildEvent(context);
            int status = context.request().response().getStatusCode();
            final String access_log = "ACCESS_LOG";
            if (status >= 500) {
                vertx.executeBlocking(f -> {
                    MDC.put(Constant.TYPE, access_log);
                    LOGGER.error(event.encode());
                    f.complete();
                }, r -> MDC.remove(Constant.TYPE));
            }
            else if (status >= 400) {
                vertx.executeBlocking(f -> {
                    MDC.put(Constant.TYPE, access_log);
                    LOGGER.warn(event.encode());
                    f.complete();
                }, r -> MDC.remove(Constant.TYPE));
            }
            else {
                vertx.executeBlocking(f -> {
                    MDC.put(Constant.TYPE, access_log);
                    LOGGER.info(event.encode());
                    f.complete();
                }, r -> MDC.remove(Constant.TYPE));
            }
            MDC.remove(Constant.TYPE);
        });
        context.next();
    }

    private JsonObject buildEvent(RoutingContext context) {
        JsonObject event = new JsonObject();
        event.put("timestamp", System.currentTimeMillis());
        event.put("component", className);
        if (Objects.nonNull(context.user()) && context.user().principal().containsKey(Constant.EMAIL)) {
            event.put(Constant.USER_ID, context.user().principal().getString(Constant.EMAIL));
        }
        if (Objects.nonNull(context.user()) && context.user().principal().containsKey(Constant.CLIENT_ID)) {
            event.put("clientId", context.user().principal().getString(Constant.CLIENT_ID));
        }
        if (Objects.nonNull(context.request().remoteAddress())) {
            event.put("remoteAddress", context.request().remoteAddress().host());
        }
        event.put("action", context.request().method());
        event.put("uri", context.request().uri());
        event.put("contentLength", context.request().response().bytesWritten());
        event.put("status", context.request().response().getStatusCode());
        String ref = context.request().headers().contains("referrer") ? context.request().headers().get("referrer") : context.request().headers().get("referer");
        if (Objects.nonNull(ref)) {
            event.put("referrer", ref);
        }
        event.put("user-agent", context.request().headers().get("user-agent"));
        return event;
    }
}
