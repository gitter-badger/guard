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


import com.demkada.guard.server.commons.model.InternalScope;
import com.demkada.guard.server.commons.model.User;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.apache.commons.validator.routines.EmailValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

class UserService {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserService.class);

    private final Vertx vertx;

    UserService(Vertx vertx) {
        this.vertx = vertx;
    }

    void getUsers(RoutingContext context) {
        context.user().isAuthorized(InternalScope.GUARD_READ_USERS.name(), ar -> {
            if (ar.succeeded()) {
                sendGetUsersEvent(context);
            }
            else if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                sendGetUsersEvent(context);
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, Constant.ACTION_NOT_ALLOWED).encode());
            }
        });
    }

    private void sendGetUsersEvent(RoutingContext context) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USERS);
        JsonObject entries = new JsonObject();
        vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded()) {
                JsonObject body = (JsonObject) reply.result().body();
                JsonArray array = body.getJsonArray(Constant.RESPONSE);
                List<JsonObject> users = array.stream().map(o -> {
                    JsonObject object = (JsonObject) o;
                    object.remove(Constant.PASS);
                    object.remove(Constant.SECURITY_QUESTION);
                    return object;
                }).collect(Collectors.toList());
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(new JsonArray(users).encode());
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    void getUserByEmail(RoutingContext context) {
        String email = context.request().getParam("email");
        if (EmailValidator.getInstance().isValid(email)) {
            context.user().isAuthorized(InternalScope.GUARD_READ_USERS.name(), ar -> {
                if (ar.succeeded()) {
                    sendGetUserByEmailEvent(context, email);
                }
                else if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                    sendGetUserByEmailEvent(context, email);
                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, Constant.ACTION_NOT_ALLOWED).encode());
                }
            });
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, Constant.NO_VALID_EMAIL_ADDRESS).encode());
        }
    }

    private void sendGetUserByEmailEvent(RoutingContext context, String email) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL);
        JsonObject entries = new JsonObject().put(Constant.EMAIL, email);
        vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded()) {
                JsonObject body = (JsonObject) reply.result().body();
                JsonObject response = body.getJsonObject(Constant.RESPONSE);
                response.remove(Constant.PASS);
                response.remove(Constant.SECURITY_QUESTION);
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(response.encode());
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    void updateUser(RoutingContext context) {
        String email = context.request().getParam(Constant.EMAIL);
        JsonObject entries = context.getBodyAsJson();
        if (EmailValidator.getInstance().isValid(email) && Objects.nonNull(entries) && !email.equalsIgnoreCase(context.user().principal().getString(Constant.EMAIL))) {
            String finalEmail = email.toLowerCase();
            context.user().isAuthorized(InternalScope.GUARD_UPDATE_USERS.name(), ar -> {
                if (ar.succeeded()) {
                    sendUserUpdateEvent(context, entries, finalEmail);
                }
                else if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                    sendUserUpdateEvent(context, entries, finalEmail);
                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, "action not allowed").encode());
                }
            });
        }
        else if (Objects.nonNull(entries)) {
            email = context.user().principal().getString(Constant.EMAIL);
            sendUserUpdateEvent(context, entries, email);
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "Not a valid email address").encode());
        }
    }

    void changePassword(RoutingContext context) {
        //TODO Should require OTP from Guard Authenticator app
        String email = context.request().getParam(Constant.EMAIL);
        JsonObject entries = context.getBodyAsJson();
        if (EmailValidator.getInstance().isValid(email) && Objects.nonNull(entries) && !email.equalsIgnoreCase(context.user().principal().getString(Constant.EMAIL))) {
            String finalEmail = email.toLowerCase();
            context.user().isAuthorized(InternalScope.GUARD_UPDATE_USERS.name(), ar -> {
                if (ar.succeeded()) {
                    sendPasswordUpdateEvent(context, entries, finalEmail);
                }
                else if (Utils.isAdmin(vertx.getOrCreateContext().config().getJsonArray(Constant.GUARD_SERVER_ADMIN), context.user().principal().getString(Constant.EMAIL))) {
                    sendPasswordUpdateEvent(context, entries, finalEmail);
                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, "action not allowed").encode());
                }
            });
        }
        else if (Objects.nonNull(entries)) {
            email = context.user().principal().getString(Constant.EMAIL);
            sendPasswordUpdateEvent(context, entries, email);
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "Not a valid email address").encode());
        }
    }

    private void sendPasswordUpdateEvent(RoutingContext context, JsonObject entries, String finalEmail) {
        if (Objects.nonNull(entries.getString(Constant.PASS)) && !entries.getString(Constant.PASS).isEmpty()) {
            DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_PASS);
            entries.put(Constant.EMAIL, finalEmail);
            vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries, options, reply -> {
                if (reply.succeeded()) {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
                }
                else {
                    Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
                }

            });
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end();
        }
    }

    private void sendUserUpdateEvent(RoutingContext context, JsonObject entries, String finalEmail) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL));
        JsonObject message = new JsonObject().put(Constant.EMAIL, finalEmail);
        vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, message, options.get(), r -> {
            if (r.succeeded()) {

                JsonObject body = (JsonObject) r.result().body();
                User saved = body.getJsonObject(Constant.RESPONSE).mapTo(User.class);

                User user = entries.mapTo(User.class);
                user.setEmail(saved.getEmail());
                user.setPwd(saved.getPwd());
                user.setSub(saved.getSub());
                user.setEmailVerified(saved.isEmailVerified());
                user.setDisable(saved.isDisable());
                user.setIdOrigin(saved.getIdOrigin());
                user.setSecurityQuestion(saved.getSecurityQuestion());
                user.setPin(saved.getPin());
                if (Objects.nonNull(user.getPhoneNumber()) && !user.getPhoneNumber().isEmpty()) {
                    user.setPhoneNumberVerified(false);
                }

                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_UPDATE_USER));
                vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)), options.get(), reply -> {
                    if (reply.succeeded()) {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
                    }
                    else {
                        Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
                    }
                });
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(r.cause()));
            }
        });
    }

}
