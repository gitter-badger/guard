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


import com.demkada.guard.server.commons.model.InternalScope;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

class ConsentService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConsentService.class);

    private final Vertx vertx;

    ConsentService(Vertx vertx) {
        this.vertx = vertx;
    }

    void createConsents(RoutingContext context) {
        try {
            JsonArray consents = context.getBodyAsJsonArray();
            if (areBaseValid(consents)) {
                AtomicReference<JsonArray> array = new AtomicReference<>();
                context.user().isAuthorized(InternalScope.GUARD_CREATE_CONSENTS.name(), ar -> {
                    if (ar.succeeded()) {
                        if (areValid(consents)) {
                            array.set(consents);
                        } else {
                            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "invalid input").encode());
                        }
                    } else {
                        array.set(new JsonArray(consents.stream()
                                .peek(c -> ((JsonObject) c).put("userEmail", context.user().principal().getString(Constant.EMAIL))).collect(Collectors.toList())));
                    }
                    AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_CONSENT));
                    AtomicReference<JsonObject> message = new AtomicReference<>(new JsonObject().put(Constant.CONSENT, array.get()));
                    vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, message.get(), options.get(), r -> {
                        if (r.succeeded() && Objects.nonNull(r.result())) {
                            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(201).end();
                        } else {
                            Utils.handleServerError(context, LOGGER, r.cause());
                        }
                    });
                });
            } else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "invalid input").encode());
            }
        } catch (Exception ex) {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "should be a json array of consents").encode());
        }
    }


    void getConsents(RoutingContext context) {
        List<String> scopes = context.queryParam(Constant.SCOPE_NAME);
        String clientId = null;
        String email = null;
        if (Objects.nonNull(context.request().getParam(Constant.CLIENT_ID)) && !context.request().getParam(Constant.CLIENT_ID).isEmpty()) {
            clientId = context.request().getParam(Constant.CLIENT_ID);
        }
        if (Objects.nonNull(context.request().getParam(Constant.USER_EMAIL)) && !context.request().getParam(Constant.USER_EMAIL).isEmpty()) {
            email = context.request().getParam(Constant.USER_EMAIL);
        }

        JsonObject entries = new JsonObject();
        if (Objects.nonNull(scopes) && !scopes.isEmpty() && Objects.nonNull(clientId) && Objects.nonNull(email)) {
            entries.put(Constant.SCOPE_NAME, new JsonArray(scopes))
                    .put(Constant.CLIENT_ID, clientId)
                    .put(Constant.USER_EMAIL, email);
        } else if (Objects.nonNull(scopes) && !scopes.isEmpty() && Objects.nonNull(clientId)) {
            entries.put(Constant.SCOPE_NAME, new JsonArray(scopes))
                    .put(Constant.CLIENT_ID, clientId);
        } else if (Objects.nonNull(email)) {
            entries.put(Constant.USER_EMAIL, email);
        }
        getConsents(context, entries);

    }

    void deleteConsent(RoutingContext context) {
        String scope = context.request().getParam(Constant.SCOPE_NAME);
        String clientId = context.request().getParam(Constant.CLIENT_ID);
        String email = context.request().getParam(Constant.USER_EMAIL);
        if (Objects.isNull(email) && context.user().principal().containsKey(Constant.EMAIL)) {
            email = context.user().principal().getString(Constant.EMAIL);
        }
        if (Objects.isNull(email) || email.isEmpty()) {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end();
        }
        if (Objects.nonNull(scope) && !scope.isEmpty() && Objects.nonNull(clientId) && !clientId.isEmpty() && Objects.nonNull(email) && !email.isEmpty()) {
            JsonObject entries = new JsonObject();
            entries.put(Constant.SCOPE_NAME, scope)
                    .put(Constant.CLIENT_ID, clientId)
                    .put(Constant.USER_EMAIL, email);
            sendDeleteEvent(context, entries);
        } else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end();
        }


    }

    private void sendDeleteEvent(RoutingContext context, JsonObject entries) {
        context.user().isAuthorized(InternalScope.GUARD_DELETE_CONSENTS.name(), ar -> {
            if (ar.succeeded() || Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                sendConsentDeleteEvent(context, entries);
            } else {
                sendDeleteEventForNonPrivilegedUser(context, entries);
            }
        });
    }

    private void sendDeleteEventForNonPrivilegedUser(RoutingContext context, JsonObject entries) {
        if (!context.user().principal().getString(Constant.EMAIL).equalsIgnoreCase(entries.getString(Constant.USER_EMAIL))) {
            entries.put(Constant.USER_EMAIL, context.user().principal().getString(Constant.EMAIL));
        }
        sendConsentDeleteEvent(context, entries);
    }

    private void sendConsentDeleteEvent(RoutingContext context, JsonObject entries) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DELETE_CONSENT));
        vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options.get(), reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
            } else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    private void getConsents(RoutingContext context, JsonObject entries) {
        context.user().isAuthorized(InternalScope.GUARD_READ_CONSENTS.name(), ar -> {
            if (ar.succeeded() || Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                sendGetConsentEvent(context, entries);
            } else if (!context.user().principal().getString(Constant.EMAIL).equalsIgnoreCase(entries.getString(Constant.USER_EMAIL))) {
                entries.put(Constant.USER_EMAIL, context.user().principal().getString(Constant.EMAIL));
                sendGetConsentEvent(context, entries);
            } else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end();
            }
        });
    }

    private void sendGetConsentEvent(RoutingContext context, JsonObject entries) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CONSENTS);
        vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                JsonObject body = (JsonObject) reply.result().body();
                JsonArray array = body.getJsonArray(Constant.RESPONSE);
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(array.encode());
            } else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    private boolean areBaseValid(JsonArray consents) {
        return consents.stream().allMatch(c -> {
            JsonObject o = (JsonObject) c;
            return Objects.nonNull(o.getString("scopeName"))
                    && !o.getString("scopeName").isEmpty()
                    && Objects.nonNull(o.getString("clientId"))
                    && !o.getString("clientId").isEmpty()
                    && Objects.nonNull(o.getString("clientName"))
                    && !o.getString("clientName").isEmpty();
        });
    }

    private boolean areValid(JsonArray consents) {
        return consents.stream().allMatch(c -> {
            JsonObject o = (JsonObject) c;
            return Objects.nonNull(o.getString("userEmail"))
                    && !o.getString("userEmail").isEmpty();
        });
    }
}
