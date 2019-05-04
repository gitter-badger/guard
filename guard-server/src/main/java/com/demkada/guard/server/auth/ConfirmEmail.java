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


import com.demkada.guard.server.commons.model.EmailInput;
import com.demkada.guard.server.commons.model.User;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
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
import java.util.concurrent.atomic.AtomicReference;

class ConfirmEmail {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfirmEmail.class);

    private final Vertx vertx;

    ConfirmEmail(Vertx vertx) {
        this.vertx = vertx;
    }

    void sendEmailConfirmationRequestMail(RoutingContext context, User finalUser, int code) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN));
        JsonObject entries = new JsonObject().put(Constant.USER, JsonObject.mapFrom(finalUser)).put(Constant.EXP, 5L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options.get(), reply -> {
            if (reply.succeeded()) {
                JsonObject response = (JsonObject) reply.result().body();
                String link = this.vertx.getOrCreateContext().config().getString(Constant.GUARD_SERVER_HOST, "https://localhost:8443") + "/#/auth/confirm-email/" + response.getString(Constant.RESPONSE);
                String contact = this.vertx.getOrCreateContext().config().getString(Constant.GUARD_CONTACT, Constant.CONTACT_EMAIL);
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_CONFIRMATION_REQUEST));

                EmailInput input = new EmailInput(finalUser, link, contact);

                if (Objects.nonNull(context.preferredLanguage()) && Constant.LOCALE_FR.equals(context.preferredLanguage().tag())) {
                    input.setLocale(context.preferredLanguage().tag());
                    input.setTitle(vertx.getOrCreateContext().config().getString(Constant.GUARD_CONFIRM_ACCOUNT_EMAIL_TITLE_FR, Constant.DEFAULT_CONFIRM_ACCOUNT_EMAIL_TITLE_FR));
                } else {
                    input.setTitle(vertx.getOrCreateContext().config().getString(Constant.GUARD_CONFIRM_ACCOUNT_EMAIL_TITLE_EN, Constant.DEFAULT_CONFIRM_ACCOUNT_EMAIL_TITLE_EN));
                }

                JsonObject emailInput = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(input));
                this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, emailInput, options.get(), r -> {
                    if (r.succeeded()) {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(code).end();
                    } else {
                        Utils.handleServerError(context, LOGGER, new GuardException(r.cause()));
                    }
                });
            } else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    void handleRequest(RoutingContext context) {
        JsonObject entries = context.getBodyAsJson();
        if (Objects.nonNull(entries.getString(Constant.EMAIL))) {
            String email = entries.getString(Constant.EMAIL);
            if (EmailValidator.getInstance().isValid(email)) {
                DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL);
                JsonObject message = new JsonObject().put(Constant.EMAIL, email);
                vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, message, options, reply -> {
                    if (reply.succeeded()) {
                        User user = new JsonObject(reply.result().body().toString()).getJsonObject(Constant.RESPONSE).mapTo(User.class);
                        if (!user.isEmailVerified()) {
                            this.sendEmailConfirmationRequestMail(context, user, 200);
                        } else {
                            String uuid = UUID.randomUUID().toString();
                            LOGGER.debug(uuid, reply.cause());
                            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "Can't sent confirmation link for this email address. Maybe it doesn't exist or it's already verified").encode());
                        }
                    } else {
                        String uuid = UUID.randomUUID().toString();
                        LOGGER.error(uuid, reply.cause());
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, "Can't sent confirmation link for this email address. Maybe it doesn't exist or it's already verified").encode());
                    }
                });
            } else {
                String uuid = UUID.randomUUID().toString();
                GuardException exception = new GuardException("Invalid email address");
                LOGGER.error(uuid, exception);
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, exception.getMessage()).encode());
            }
        }
        else {
            String uuid = UUID.randomUUID().toString();
            GuardException exception = new GuardException("Invalid email address");
            LOGGER.error(uuid, exception);
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(400).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 400).put(Constant.ERROR_MESSAGE, exception.getMessage()).encode());
        }
    }

    void handleResult(RoutingContext context) {
        String key = context.pathParam("confirmation_key");
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, new JsonObject().put(Constant.PAYLOAD, key), options.get(), reply -> {
            if (reply.succeeded()) {
                JsonObject response = (JsonObject) reply.result().body();
                User user = Utils.getUserFromPrincipal(response);
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL));
                JsonObject message = new JsonObject().put(Constant.EMAIL, user.getEmail());
                vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, message, options.get(), ru -> {
                    if (ru.succeeded()) {
                        if (!new JsonObject(ru.result().body().toString()).getJsonObject(Constant.RESPONSE).mapTo(User.class).isEmailVerified()) {
                            changeEmailStatus(context, options, user);
                        } else {
                            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
                        }
                    } else {
                        String uuid = UUID.randomUUID().toString();
                        LOGGER.error(uuid, reply.cause());
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR_MESSAGE, "Unable to confirm email").encode());
                    }
                });
            } else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                        .setStatusCode(401).end();
            }
        });
    }

    private void changeEmailStatus(RoutingContext context, AtomicReference<DeliveryOptions> options, User user) {
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_EMAIL_STATUS));
        JsonObject entries = new JsonObject().put(Constant.EMAIL, user.getEmail())
                .put(Constant.STATUS, true);
        vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries, options.get(), eResultMessage -> {
            if (eResultMessage.succeeded()) {
                String contact = vertx.getOrCreateContext().config().getString(Constant.GUARD_CONTACT, Constant.CONTACT_EMAIL);
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_CONFIRMATION_RESULT));

                EmailInput input = new EmailInput(user, contact);

                if (Objects.nonNull(context.preferredLanguage()) && Constant.LOCALE_FR.equals(context.preferredLanguage().tag())) {
                    input.setLocale(context.preferredLanguage().tag());
                    input.setTitle(vertx.getOrCreateContext().config().getString(Constant.GUARD_VERIFIED_ACCOUNT_EMAIL_TITLE_FR, Constant.DEFAULT_VERIFIED_ACCOUNT_EMAIL_TITLE_FR));
                } else {
                    input.setTitle(vertx.getOrCreateContext().config().getString(Constant.GUARD_VERIFIED_ACCOUNT_EMAIL_TITLE_EN, Constant.DEFAULT_VERIFIED_ACCOUNT_EMAIL_TITLE_EN));
                }

                JsonObject emailInput = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(input));
                this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, emailInput, options.get(), r -> {
                    if (r.succeeded()) {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                                .setStatusCode(200)
                                .end();
                    } else {
                        Utils.handleServerError(context, LOGGER, new GuardException(r.cause()));
                    }
                });
            } else {
                Utils.handleServerError(context, LOGGER, eResultMessage.cause());
            }
        });
    }
}
