package com.demkada.guard.server.clients;

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


import com.demkada.guard.server.commons.model.Client;
import com.demkada.guard.server.commons.model.ClientType;
import com.demkada.guard.server.commons.model.InternalScope;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.StringHashUtil;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.VertxContextPRNG;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

class ClientService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientService.class);

    private final Vertx vertx;

    ClientService(Vertx vertx) {
        this.vertx = vertx;
    }

    public void createClient(RoutingContext context) {
        try {
            JsonObject body = context.getBodyAsJson();
            Client client = body.mapTo(Client.class);
            if (Objects.nonNull(client) && isBaseValid(client)) {
                context.user().isAuthorized(InternalScope.GUARD_CREATE_CLIENTS.name(), ar -> {
                    if (ar.succeeded()) {
                        if (isValid(client)) {
                            sendCreateEvent(context, client);
                        }
                        else {
                            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "invalid input").encode());
                        }
                    }
                    else {
                        processEndUserRequest(context, client);
                    }
                });
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "invalid input").encode());
            }
        }
        catch (Exception e) {
            String uuid = UUID.randomUUID().toString();
            GuardException exception = new GuardException("invalid input");
            LOGGER.debug(uuid, exception);
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, exception.getMessage()).encode());
        }
    }

    private void processEndUserRequest(RoutingContext context, Client client) {
        Set<String> managers = client.getManagers();
        managers.add(context.user().principal().getString(Constant.EMAIL));
        client.setManagers(managers);
        client.setId(UUID.randomUUID().toString());
        if (client.getClientType().equals(ClientType.CONFIDENTIAL)) {
            client.setSecret(VertxContextPRNG.current(vertx).nextString(32));
        }
        else {
            client.setSecret(null);
        }
        sendCreateEvent(context, client);
    }


    public void getClients(RoutingContext context) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENTS);
        JsonObject entries = new JsonObject();
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                JsonObject body = (JsonObject) reply.result().body();
                JsonArray array = body.getJsonArray(Constant.RESPONSE);
                List<JsonObject> clients = array.stream().map(o -> {
                    JsonObject object = (JsonObject) o;
                    object.remove("secret");
                    object.remove("redirectUris");
                    object.remove("cert");
                    object.remove("certSubjectDn");
                    object.remove("labels");
                    object.remove("accessPolicies");
                    return object;
                }).collect(Collectors.toList());
                if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(new JsonArray(clients).encode());
                }
                else {
                    List response = clients.stream().filter(c -> !c.getBoolean(Constant.DISABLE)).collect(Collectors.toList());
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(new JsonArray(response).encode());
                }
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    public void getClientById(RoutingContext context) {
        String id = context.pathParam("id");
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENT_BY_ID);
        JsonObject entries = new JsonObject().put(Constant.CLIENT_ID, id);
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                JsonObject body = (JsonObject) reply.result().body();
                JsonObject response = body.getJsonObject(Constant.RESPONSE);
                response.remove("secret");

                if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(response.encode());
                }
                else if (response.getBoolean(Constant.DISABLE)) {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
                }
                else {
                    context.user().isAuthorized(InternalScope.GUARD_READ_CLIENTS.name(), ar -> {
                        if (ar.succeeded()) {
                            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(response.encode());
                        }
                        else {
                            getClientByIdForNonPrivilegedUser(context, response);
                        }
                    });
                }
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
            }
        });
    }

    private void getClientByIdForNonPrivilegedUser(RoutingContext context, JsonObject response) {
        Client client = response.mapTo(Client.class);
        if (client.getManagers().contains(context.user().principal().getString(Constant.EMAIL))) {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(response.encode());
        }
        else {
            response.remove("secret");
            response.remove("clientType");
            response.remove("redirectUris");
            response.remove("managers");
            response.remove("accessPolicies");
            response.remove("disable");
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(response.encode());
        }
    }


    public void updateClient(RoutingContext context) {
        try {
            String id = context.pathParam("id");
            JsonObject b = context.getBodyAsJson();
            Client client = b.mapTo(Client.class);
            client.setId(id);
            DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENT_BY_ID);
            JsonObject entries = new JsonObject().put(Constant.CLIENT_ID, client.getId());
            vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, reply -> {
                if (reply.succeeded() && Objects.nonNull(reply.result())) {
                    JsonObject body = (JsonObject) reply.result().body();
                    JsonObject response = body.getJsonObject(Constant.RESPONSE);
                    Client saved = response.mapTo(Client.class);
                    if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                        client.setSecret(saved.getSecret());
                        sendClientUpdateEvent(context, client, saved);
                    } else if (!saved.isDisable()) {
                        context.user().isAuthorized(InternalScope.GUARD_UPDATE_CLIENTS.name(), ar -> {
                            if (ar.succeeded()) {
                                sendClientUpdateEvent(context, client, saved);
                            } else {
                                updateClientByNonPrivilegedUser(context, client, saved);
                            }
                        });
                    } else {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
                    }
                } else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
                }
            });
        }
        catch (Exception e) {
            String uuid = UUID.randomUUID().toString();
            GuardException exception = new GuardException("invalid input");
            LOGGER.debug(uuid, exception);
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, exception.getMessage()).encode());
        }

    }

    void disableClient(RoutingContext context) {
        String id = context.pathParam("id");
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENT_BY_ID);
        JsonObject entries = new JsonObject().put(Constant.CLIENT_ID, id);
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                JsonObject body = (JsonObject) reply.result().body();
                JsonObject response = body.getJsonObject(Constant.RESPONSE);
                Client saved = response.mapTo(Client.class);
                if (!saved.isDisable()) {
                    context.user().isAuthorized(InternalScope.GUARD_UPDATE_CLIENTS.name(), ar -> {
                        if (ar.succeeded()) {
                            sendDisableEvent(context, saved);
                        }
                        else if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                            sendDisableEvent(context, saved);
                        }
                        else {
                            disableByNonPrivilegedUser(context, saved);
                        }
                    });

                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
                }
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
            }
        });

    }

    private void disableByNonPrivilegedUser(RoutingContext context, Client saved) {
        if (saved.getManagers().contains(context.user().principal().getString(Constant.EMAIL))) {
            sendDisableEvent(context, saved);
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end();
        }
    }

    private void sendDisableEvent(RoutingContext context, Client saved) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_CLIENT_STATUS);
        JsonObject entries = new JsonObject().put(Constant.CLIENT_ID, saved.getId()).put(Constant.STATUS, true);
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
            }
        });
    }

    private void updateClientByNonPrivilegedUser(RoutingContext context, Client client, Client saved) {
        if (saved.getManagers().contains(context.user().principal().getString(Constant.EMAIL))) {
            client.setSecret(saved.getSecret());
            sendClientUpdateEvent(context, client, saved);
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end();
        }
    }

    public void changeStatus(RoutingContext context) {
        if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
            String id = context.pathParam("id");
            DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_CLIENT_STATUS);
            JsonObject entries = new JsonObject().put(Constant.CLIENT_ID, id).put(Constant.STATUS, context.getBodyAsJson().getBoolean(Constant.STATUS));
            vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, reply -> {
                if (reply.succeeded() && Objects.nonNull(reply.result())) {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
                }
            });
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
        }
    }

    public void changeSecret(RoutingContext context) {
        String id = context.pathParam("id");
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENT_BY_ID);
        JsonObject entries = new JsonObject().put(Constant.CLIENT_ID, id);
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                JsonObject body = (JsonObject) reply.result().body();
                Client saved = body.getJsonObject(Constant.RESPONSE).mapTo(Client.class);
                JsonObject payload = new JsonObject().put(Constant.CLIENT_ID, saved.getId()).put(Constant.CLIENT_SECRET, VertxContextPRNG.current(vertx).nextString(32));
                if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                    sendClientSecretChangeEvent(context, payload);
                }
                else if (saved.isDisable()) {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
                }
                else {
                    context.user().isAuthorized(InternalScope.GUARD_READ_CLIENTS.name(), ar -> {
                        if (ar.succeeded()) {
                            sendClientSecretChangeEvent(context, payload);
                        }
                        else {
                            changeSecretByNonPrivilegedUser(context, saved, payload);
                        }
                    });
                }
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(404).end();
            }
        });
    }

    private void changeSecretByNonPrivilegedUser(RoutingContext context, Client saved, JsonObject payload) {
        if (saved.getManagers().contains(context.user().principal().getString(Constant.EMAIL))) {
            sendClientSecretChangeEvent(context, payload);
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end();
        }
    }

    private void sendClientSecretChangeEvent(RoutingContext context, JsonObject payload) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_SECRET));
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, payload, options.get(), reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(payload.encode());
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    private void sendClientUpdateEvent(RoutingContext context, Client actual, Client saved) {
        actual.setId(saved.getId());
        if (Objects.isNull(actual.getSecret()) || actual.getSecret().isEmpty()) {
            actual.setSecret(saved.getSecret());
            executeUpdateEvent(context, actual, saved);
        }
        else {
            StringHashUtil.generateHash(vertx, actual.getSecret(), ar -> {
                if (ar.succeeded()) {
                    actual.setSecret(ar.result());
                    executeUpdateEvent(context, actual, saved);
                }
                else {
                    Utils.handleServerError(context, LOGGER, new GuardException(ar.cause()));
                }
            });
        }

    }

    private void executeUpdateEvent(RoutingContext context, Client actual, Client saved) {
        Set<String> managers = saved.getManagers();
        if (context.user().principal().containsKey(Constant.EMAIL)) {
            managers.add(context.user().principal().getString(Constant.EMAIL));
        }
        actual.setManagers(managers);
        actual.setDisable(saved.isDisable());
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_CLIENT));
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, new JsonObject().put(Constant.CLIENT, JsonObject.mapFrom(actual)), options.get(), reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    private void sendCreateEvent(RoutingContext context, Client client) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CLIENT_BY_ID));
        AtomicReference<JsonObject> message = new AtomicReference<>(new JsonObject().put(Constant.CLIENT_ID, client.getId()));
        vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, message.get(), options.get(), reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result()) && Objects.nonNull(reply.result().body()) && !new JsonObject(reply.result().body().toString()).getJsonObject(Constant.RESPONSE).getString("id").isEmpty()) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(409).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 409).put(Constant.ERROR_MESSAGE, "Client already exist").encode());
            }
            else {
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_CLIENT));
                message.set(new JsonObject().put(Constant.CLIENT, JsonObject.mapFrom(client)));
                vertx.eventBus().send(Constant.CLIENT_MANAGER_QUEUE, message.get(), options.get(), r -> {
                    if (r.succeeded() && Objects.nonNull(r.result())) {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(201).end(JsonObject.mapFrom(client).encode());
                    }
                    else {
                        Utils.handleServerError(context, LOGGER,  reply.cause());
                    }
                });
            }
        });
    }

    private boolean isBaseValid(Client client) {
        boolean valid = true;

        if (Objects.isNull(client.getName()) || client.getName().isEmpty()) {
            valid = false;
        }
        if (Objects.isNull(client.getDescription()) || client.getDescription().isEmpty()) {
            valid = false;
        }
        if (Objects.isNull(client.getClientType())) {
            valid = false;
        }
        return valid;
    }

    private boolean isValid(Client client) {
        boolean valid = true;
        if (Objects.isNull(client.getId()) || client.getId().isEmpty()) {
            valid = false;
        }
        if (Objects.isNull(client.getSecret()) || client.getSecret().isEmpty()) {
            valid = false;
        }
        if (client.getManagers().isEmpty()) {
            valid = false;
        }
        return valid;
    }
}
