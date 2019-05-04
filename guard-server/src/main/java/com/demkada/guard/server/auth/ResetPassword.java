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


import com.demkada.guard.server.commons.SecurityQuestion;
import com.demkada.guard.server.commons.model.EmailInput;
import com.demkada.guard.server.commons.model.QuestionId;
import com.demkada.guard.server.commons.model.User;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.AsyncResult;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.apache.commons.validator.routines.EmailValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

class ResetPassword {

    private static final Logger LOGGER = LoggerFactory.getLogger(ResetPassword.class);

    private final Vertx vertx;
    private static final String ERROR_MESSAGE = "Password reset request for email: ";

    ResetPassword(Vertx vertx) {
        this.vertx = vertx;
    }

    void handleRequest(RoutingContext context) {
        JsonObject entries = context.getBodyAsJson();
        if (Objects.nonNull(entries.getString(Constant.EMAIL))) {
            String email = entries.getString(Constant.EMAIL).toLowerCase();
            if (EmailValidator.getInstance().isValid(email)) {
                DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL);
                JsonObject message = new JsonObject().put(Constant.EMAIL, email);
                vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, message, options, reply -> {
                    if (reply.succeeded()) {
                        User user = new JsonObject(reply.result().body().toString()).getJsonObject(Constant.RESPONSE).mapTo(User.class);
                        if (user.isEmailVerified()) {
                            user = Utils.sanitizeUser(user);
                            sendPasswordResetLink(context, user);
                        }
                        else {
                            sendErrorMail(context, email, null);
                        }
                    }
                    else {
                        sendErrorMail(context, email, reply.cause());
                    }
                });
            }
            else {
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

    private void sendErrorMail(RoutingContext context, String email, Throwable cause) {
        if (Objects.nonNull(cause)) {
            LOGGER.warn(ERROR_MESSAGE + email, cause);
        }
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_PASS_RESET_REQUEST_KO);
        String contact = this.vertx.getOrCreateContext().config().getString(Constant.GUARD_CONTACT, Constant.CONTACT_EMAIL);
        User user = new User();
        user.setEmail(email);
        EmailInput input = new EmailInput(user, contact);

        if (Objects.nonNull(context.preferredLanguage()) && Constant.LOCALE_FR.equals(context.preferredLanguage().tag())){
            input.setLocale(context.preferredLanguage().tag());
            input.setTitle(vertx.getOrCreateContext().config().getString(Constant.GUARD_RESET_PASS_REQUEST_EMAIL_TITLE_FR, Constant.DEFAULT_RESET_PASS_REQUEST_EMAIL_TITLE_FR));
        }
        else {
            input.setTitle(vertx.getOrCreateContext().config().getString(Constant.GUARD_RESET_PASS_REQUEST_EMAIL_TITLE_EN, Constant.DEFAULT_RESET_PASS_REQUEST_EMAIL_TITLE_EN));
        }

        JsonObject emailInput = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(input));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, emailInput, options, r -> {
            if (r.succeeded()) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(r.cause()));
            }
        });
    }

    private void sendPasswordResetLink(RoutingContext context, User user) {
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN));
        JsonObject object = new JsonObject().put(Constant.USER, JsonObject.mapFrom(user)).put(Constant.EXP, 5L);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, object, options.get(), reply -> {
            if (reply.succeeded()) {
                JsonObject response = (JsonObject) reply.result().body();
                String link = this.vertx.getOrCreateContext().config().getString(Constant.GUARD_SERVER_HOST, "https://localhost:8443") + "/#/auth/reset-password/" + response.getString(Constant.RESPONSE);
                String contact = this.vertx.getOrCreateContext().config().getString(Constant.GUARD_CONTACT, Constant.CONTACT_EMAIL);
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_PASS_RESET_REQUEST_OK));

                EmailInput input = new EmailInput(user, link, contact);

                if (Objects.nonNull(context.preferredLanguage()) && Constant.LOCALE_FR.equals(context.preferredLanguage().tag())) {
                    input.setLocale(context.preferredLanguage().tag());
                    input.setTitle(vertx.getOrCreateContext().config().getString(Constant.GUARD_RESET_PASS_REQUEST_EMAIL_TITLE_FR, Constant.DEFAULT_RESET_PASS_REQUEST_EMAIL_TITLE_FR));
                }
                else {
                    input.setTitle(vertx.getOrCreateContext().config().getString(Constant.GUARD_RESET_PASS_REQUEST_EMAIL_TITLE_EN, Constant.DEFAULT_RESET_PASS_REQUEST_EMAIL_TITLE_EN));
                }

                JsonObject emailInput = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(input));
                this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, emailInput, options.get(), r -> {
                    if (r.succeeded()) {
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
                    }
                    else {
                        Utils.handleServerError(context, LOGGER, new GuardException(r.cause()));
                    }
                });
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(reply.cause()));
            }
        });
    }

    void handleResult(RoutingContext context) {
        String key = context.pathParam("reset_key");
        JsonObject entries = context.getBodyAsJson();
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, new JsonObject().put(Constant.PAYLOAD, key), options.get(), reply -> {
            if (reply.succeeded()) {
                JsonObject response = (JsonObject) reply.result().body();
                User sanitizeUser = Utils.getUserFromPrincipal(response);
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL));
                AtomicReference<JsonObject> message = new AtomicReference<>(new JsonObject().put(Constant.EMAIL, sanitizeUser.getEmail()));
                vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, message.get(), options.get(), res -> {
                    if (shouldAcceptPasswordChange(entries, res)) {
                        sendPasswordChangeEvent(context, entries, options, sanitizeUser);
                    }
                    else {
                        String uuid = UUID.randomUUID().toString();
                        LOGGER.error(uuid, ERROR_MESSAGE + sanitizeUser.getEmail(), res.cause());
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, "Error when trying to change password").encode());
                    }
                });
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(401).end();
            }
        });
    }

    private void sendPasswordChangeEvent(RoutingContext context, JsonObject entries, AtomicReference<DeliveryOptions> options, User sanitizeUser) {
        entries.put(Constant.EMAIL, sanitizeUser.getEmail());
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_CHANGE_PASS));
        vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, entries, options.get(), r -> {
            if (r.succeeded() && Objects.nonNull(r.result())) {
                sendPasswordChangedEmail(context, options, sanitizeUser);
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(r.cause()));
            }
        });
    }

    private void sendPasswordChangedEmail(RoutingContext context, AtomicReference<DeliveryOptions> options, User publicUser) {
        String contact = this.vertx.getOrCreateContext().config().getString(Constant.GUARD_CONTACT, Constant.CONTACT_EMAIL);
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_PASS_RESET_RESULT));

        EmailInput input = new EmailInput(publicUser, contact);

        if(Objects.nonNull(context.preferredLanguage()) && Constant.LOCALE_FR.equals(context.preferredLanguage().tag())) {
            input.setLocale(context.preferredLanguage().tag());
            input.setTitle(vertx.getOrCreateContext().config().getString(Constant.GUARD_CHANGE_PASS_SUCCESS_EMAIL_TITLE_FR, Constant.DEFAULT_CHANGE_PASS_SUCCESS_EMAIL_TITLE_FR));
        }
        else {
            input.setTitle(vertx.getOrCreateContext().config().getString(Constant.GUARD_CHANGE_PASS_SUCCESS_EMAIL_TITLE_EN, Constant.DEFAULT_CHANGE_PASS_SUCCESS_EMAIL_TITLE_EN));
        }

        JsonObject emailInput = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(input));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, emailInput, options.get(), r -> {
            if (r.succeeded()) {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end();
            }
            else {
                Utils.handleServerError(context, LOGGER, new GuardException(r.cause()));
            }
        });
    }

    private boolean shouldAcceptPasswordChange(JsonObject entries, AsyncResult<Message<Object>> ar) {
        if (!ar.succeeded()) {
            return false;
        }
        if (Objects.isNull(entries.getString(Constant.PASS))
                || entries.getString(Constant.PASS).isEmpty()
                || Objects.isNull(entries.getJsonObject(Constant.SECURITY_QUESTION))
                || Objects.isNull(entries.getJsonObject(Constant.SECURITY_QUESTION).getMap())) {
            return false;
        }

        User user = new JsonObject(ar.result().body().toString()).getJsonObject(Constant.RESPONSE).mapTo(User.class);
        Map<String, Object> secQuestion = entries.getJsonObject(Constant.SECURITY_QUESTION).getMap();
        AtomicBoolean response = new AtomicBoolean(true);
        secQuestion.forEach((k, v) -> {
            if (!user.getSecurityQuestion().get(QuestionId.valueOf(k)).equalsIgnoreCase(String.valueOf(v))) {
                response.set(false);
            }
        });

        return response.get();
    }

    public void handleAuthorization(RoutingContext context) {
        String key = context.pathParam("reset_key");
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN));
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, new JsonObject().put(Constant.PAYLOAD, key), options.get(), reply -> {
            if (reply.succeeded()) {
                JsonObject response = (JsonObject) reply.result().body();
                User user = Utils.getUserFromPrincipal(response);
                options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_USER_BY_EMAIL));
                JsonObject message = new JsonObject().put(Constant.EMAIL, user.getEmail());
                vertx.eventBus().send(Constant.USER_MANAGER_QUEUE, message, options.get(), res -> {
                    if (res.succeeded()) {
                        JsonArray resp = new JsonArray();
                        SecurityQuestion questions = new SecurityQuestion();

                        if(Objects.nonNull(context.preferredLanguage()) && Constant.LOCALE_FR.equals(context.preferredLanguage().tag())) {
                            new JsonObject(res.result().body().toString()).getJsonObject(Constant.RESPONSE).mapTo(User.class).getSecurityQuestion().keySet().forEach(id -> resp.add(new JsonObject().put(String.valueOf(id), questions.getFrenchQuestions().get(id))));
                        }
                        else {
                            new JsonObject(res.result().body().toString()).getJsonObject(Constant.RESPONSE).mapTo(User.class).getSecurityQuestion().keySet().forEach(id -> resp.add(new JsonObject().put(String.valueOf(id), questions.getEnglishQuestions().get(id))));
                        }
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(200).end(resp.encode());
                    }
                    else {
                        String uuid = UUID.randomUUID().toString();
                        LOGGER.error(uuid, ERROR_MESSAGE + user.getEmail(), res.cause());
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, "Error when authorizing password change").encode());
                    }
                });
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(403).end(new JsonObject().put(Constant.HTTP_STATUS_CODE, 403).put(Constant.ERROR_MESSAGE, "Invalid password reset link").encode());
            }
        });
    }
}
