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


import com.demkada.guard.server.commons.model.User;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.apache.commons.validator.routines.EmailValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.UUID;

class Register {

    private static final Logger LOGGER = LoggerFactory.getLogger(Register.class);

    private final Vertx vertx;
    private final ConfirmEmail confirmEmail;

    Register(Vertx vertx, ConfirmEmail confirmEmail) {
        this.vertx = vertx;
        this.confirmEmail = confirmEmail;
    }

    void handle(RoutingContext context) {
        try {
            JsonObject entries = context.getBodyAsJson();
            User user = entries.mapTo(User.class);
            if (Objects.nonNull(user) && isValid(user)) {
                user.setEmail(user.getEmail().toLowerCase());
                user.setSub(user.getEmail());
                user.setIdOrigin(Constant.GUARD);
                if (Objects.nonNull(user.getPin())) {
                    user.setPin(Utils.stringToSha256ToBase32(user.getPin()));
                }
                DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL);
                JsonObject message = new JsonObject().put(Constant.EMAIL, user.getEmail());
                vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, message, options, reply -> {
                    if (reply.succeeded() && Objects.nonNull(reply.result()) && !new JsonObject(reply.result().body().toString()).getJsonObject(Constant.RESPONSE).getString(Constant.EMAIL).isEmpty()) {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(409).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 409).put(Constant.ERROR_MESSAGE, "User already exist").encode());
                    }
                    else {
                        createUser(context, user);
                    }
                });
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "invalid input").encode());
            }
        }
        catch (Exception e) {
            String uuid = UUID.randomUUID().toString();
            LOGGER.error(uuid, e);
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "invalid input").encode());
        }
    }

    private void createUser(RoutingContext context, User user) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_INSERT_USER);
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user));
        vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded() && Objects.nonNull(reply.result())) {
                confirmEmail.sendEmailConfirmationRequestMail(context, user, 201);
            }
            else {
                Utils.handleServerError(context, LOGGER,  reply.cause());
            }
        });
    }

    private boolean isValid(User user) {
        boolean valid = true;
        if (!EmailValidator.getInstance().isValid(user.getEmail())) {
            valid = false;
        }
        if (Objects.isNull(user.getGivenName()) || user.getGivenName().isEmpty()) {
            valid = false;
        }
        if (Objects.isNull(user.getFamilyName()) || user.getFamilyName().isEmpty()) {
            valid = false;
        }
        if (Objects.isNull(user.getPwd()) || user.getPwd().isEmpty()) {
            valid = false;
        }
        if (Objects.isNull(user.getSecurityQuestion())
                || user.getSecurityQuestion().isEmpty()
                || 2 != user.getSecurityQuestion().size()
                || user.getSecurityQuestion().keySet().stream().anyMatch(
                e -> Objects.isNull(user.getSecurityQuestion().get(e))
                        || user.getSecurityQuestion().get(e).isEmpty())) {
            valid = false;
        }
        //TODO validate PIN on user creation
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


        return valid;
    }
}
