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


import com.demkada.guard.server.commons.model.InternalScope;
import com.demkada.guard.server.commons.model.Scope;
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
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

class ScopeService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScopeService.class);

    private final Vertx vertx;

    ScopeService(Vertx vertx) {
        this.vertx = vertx;
    }

    public void createScope(RoutingContext context) {
        JsonObject body = context.getBodyAsJson();
        Scope scope = body.mapTo(Scope.class);
        if (isValid(scope)) {
            if (scope.getRefreshTokenTTL() == 0) {
                scope.setRefreshTokenTTL((int) Constant.DEFAULT_REFRESH_TOKEN_TTL);
            }
            if (scope.getConsentTTL() == 0) {
                scope.setConsentTTL((int) (long) Constant.DEFAULT_CONSENT_TTL);
            }
            context.user().isAuthorized(InternalScope.GUARD_CREATE_SCOPES.name(), ar -> {
                if (ar.succeeded()) {
                    sendCreateEvent(context, scope);
                }
                else {
                    Set<String> managers = scope.getManagers();
                    managers.add(context.user().principal().getString(Constant.EMAIL));
                    scope.setManagers(managers);
                    sendCreateEvent(context, scope);
                }
            });
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 409).put(Constant.ERROR_MESSAGE, "invalid input").encode());
        }
    }

    public void getScopes(RoutingContext context) {
        List<String> scopes = context.queryParam(Constant.NAME);
        JsonObject entries = new JsonObject();
        if (Objects.nonNull(scopes) && !scopes.isEmpty()) {
            entries.put(Constant.SCOPE_NAME, new JsonArray(scopes));
        }
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPES);
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                JsonObject body = (JsonObject) reply.result().body();
                JsonArray array = body.getJsonArray(Constant.RESPONSE);
                List<JsonObject> resp = array.stream().map(o -> {
                    JsonObject object = (JsonObject) o;
                    object.remove("restricted");
                    object.remove("machineMFA");
                    object.remove("clientIdList");
                    return object;
                }).collect(Collectors.toList());
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(new JsonArray(resp).encode());
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    public void getScopeByName(RoutingContext context) {
        String name = context.pathParam("name");
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPE_BY_NAME);
        JsonObject entries = new JsonObject().put(Constant.SCOPE_NAME, name);
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                JsonObject body = (JsonObject) reply.result().body();
                JsonObject response = body.getJsonObject(Constant.RESPONSE);
                if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(response.encode());
                }
                else {
                    context.user().isAuthorized(InternalScope.GUARD_READ_SCOPES.name(), ar -> {
                        if (ar.succeeded()) {
                            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(response.encode());
                        }
                        else {
                            getScopeByNameForNonPrivilegedUser(context, response);
                        }
                    });
                }
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
            }
        });

    }


    public void updateScope(RoutingContext context) {
        String name = context.pathParam("name");
        JsonObject body = context.getBodyAsJson();
        Scope scope = body.mapTo(Scope.class);
        scope.setName(name);
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPE_BY_NAME);
        JsonObject entries = new JsonObject().put(Constant.SCOPE_NAME, name);
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                JsonObject b = (JsonObject) reply.result().body();
                JsonObject response = b.getJsonObject(Constant.RESPONSE);
                Scope saved = response.mapTo(Scope.class);
                context.user().isAuthorized(InternalScope.GUARD_UPDATE_SCOPES.name(), ar -> {
                    if (ar.succeeded()) {
                        sendScopeUpdateEvent(context, scope, saved);
                    }
                    else if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                        sendScopeUpdateEvent(context, scope, saved);
                    }
                    else {
                        updateScopeByNonPrivilegedUser(context, scope, saved);
                    }
                });

            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
            }
        });

    }


    public void deleteScope(RoutingContext context) {
        String name = context.pathParam("name");
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPE_BY_NAME);
        JsonObject entries = new JsonObject().put(Constant.SCOPE_NAME, name);
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                JsonObject body = (JsonObject) reply.result().body();
                JsonObject response = body.getJsonObject(Constant.RESPONSE);
                Scope saved = response.mapTo(Scope.class);
                context.user().isAuthorized(InternalScope.GUARD_UPDATE_SCOPES.name(), ar -> {
                    if (ar.succeeded()) {
                        sendScopeDeleteEvent(context, saved);
                    }
                    else if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                        sendScopeDeleteEvent(context, saved);
                    }
                    else {
                        deleteScopeByNonPrivilegedUser(context, saved);
                    }
                });

            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
            }
        });
    }

    private void deleteScopeByNonPrivilegedUser(RoutingContext context, Scope saved) {
        if (Objects.nonNull(saved.getManagers()) && saved.getManagers() instanceof Set && saved.getManagers().contains(context.user().principal().getString(Constant.EMAIL))) {
            sendScopeDeleteEvent(context, saved);
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end();
        }
    }

    private void sendScopeDeleteEvent(RoutingContext context, Scope saved) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DELETE_SCOPE));
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, new JsonObject().put(Constant.SCOPE_NAME, saved.getName()), options.get(), reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    private boolean isValid(Scope scope) {
        boolean valid = true;
        if (Objects.isNull(scope)) {
            valid = false;
        }
        else {
            if (Objects.isNull(scope.getName()) || scope.getName().isEmpty()) {
                valid = false;
            }
            if (Objects.isNull(scope.getEnDescription()) || scope.getEnDescription().isEmpty()) {
                valid = false;
            }
        }

        return valid;
    }

    private void sendCreateEvent(RoutingContext context, Scope scope) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPE_BY_NAME));
        AtomicReference<JsonObject> message = new AtomicReference<>(new JsonObject().put(Constant.NAME, scope.getName()));
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, message.get(), options.get(), reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result()) && Objects.nonNull(reply.result().body()) && !new JsonObject(reply.result().body().toString()).getJsonObject(Constant.RESPONSE).getString(Constant.NAME).isEmpty()) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(409).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 409).put(Constant.ERROR_MESSAGE, "Scope already exist").encode());
            }
            else {
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_SCOPE));
                message.set(new JsonObject().put(Constant.SCOPE, JsonObject.mapFrom(scope)));
                vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, message.get(), options.get(), r -> {
                    if (r.succeeded() && Objects.nonNull(r.result())) {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(201).end(JsonObject.mapFrom(scope).encode());
                    }
                    else {
                        Utils.handleServerError(context, LOGGER,  r.cause());
                    }
                });
            }
        });
    }

    private void updateScopeByNonPrivilegedUser(RoutingContext context, Scope scope, Scope saved) {
        if (Objects.nonNull(saved.getManagers()) && saved.getManagers() instanceof Set && saved.getManagers().contains(context.user().principal().getString(Constant.EMAIL))) {
            sendScopeUpdateEvent(context, scope, saved);
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end();
        }
    }

    private void sendScopeUpdateEvent(RoutingContext context, Scope scope, Scope saved) {
        scope.setName(saved.getName());
        Set<String> managers = scope.getManagers();
        managers.add(context.user().principal().getString(Constant.EMAIL));
        scope.setManagers(managers);
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_SCOPE));
        vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, new JsonObject().put(Constant.SCOPE, JsonObject.mapFrom(scope)), options.get(), reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    private void getScopeByNameForNonPrivilegedUser(RoutingContext context, JsonObject response) {
        Scope scope = response.mapTo(Scope.class);
        if (Objects.nonNull(scope.getManagers()) && scope.getManagers() instanceof Set && scope.getManagers().contains(context.user().principal().getString(Constant.EMAIL))) {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(response.encode());
        }
        else {
            response.remove("restricted");
            response.remove("machineMFA");
            response.remove("clientIdList");
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(response.encode());
        }
    }
}
