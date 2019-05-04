package com.demkada.guard.server.mail;

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
import com.demkada.guard.server.commons.model.ErrorCodes;
import com.demkada.guard.server.commons.utils.Constant;
import fr.sii.ogham.core.service.MessagingService;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;

class PasswordReset extends MailService {


    PasswordReset(Vertx vertx, MessagingService service) {
        super(vertx, service);
    }

    void sendResetRequestOk(Message<JsonObject> message) {
        EmailInput emailInput = message.body().getJsonObject(Constant.EMAIL_INPUT).mapTo(EmailInput.class);
        String templatePath;
        if (Constant.LOCALE_FR.equals(emailInput.getLocale())) {
            templatePath = "fr/password-reset-request-ok.html";
        } else {
            templatePath = "en/password-reset-request-ok.html";
        }

        this.sendSimpleEmail(emailInput,templatePath , ar -> {
            if (ar.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, "done"));
            }
            else {
                message.fail(ErrorCodes.IMPOSSIBLE_TO_SEND_EMAIL.ordinal(), ar.cause().getMessage());
            }
        });
    }

    void sendResetRequestKo(Message<JsonObject> message) {
        EmailInput emailInput = message.body().getJsonObject(Constant.EMAIL_INPUT).mapTo(EmailInput.class);
        String templatePath;
        if (Constant.LOCALE_FR.equals(emailInput.getLocale())) {
            templatePath = "fr/password-reset-request-ko.html";
        } else {
            templatePath = "en/password-reset-request-ko.html";
        }
        this.sendSimpleEmail(emailInput,templatePath, ar -> {
            if (ar.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, "done"));
            }
            else {
                message.fail(ErrorCodes.IMPOSSIBLE_TO_SEND_EMAIL.ordinal(), ar.cause().getMessage());
            }
        });
    }

    void sendResetResult(Message<JsonObject> message) {
        EmailInput emailInput = message.body().getJsonObject(Constant.EMAIL_INPUT).mapTo(EmailInput.class);
        String templatePath;
        if ("fr".equals(emailInput.getLocale())) {
            templatePath = "fr/password-reset-result.html";
        } else {
            templatePath = "en/password-reset-result.html";
        }
        this.sendSimpleEmail(emailInput,templatePath, ar -> {
            if (ar.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, "done"));
            }
            else {
                message.fail(ErrorCodes.IMPOSSIBLE_TO_SEND_EMAIL.ordinal(), ar.cause().getMessage());
            }
        });
    }
}
