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


import com.demkada.guard.server.commons.model.ErrorCodes;
import com.demkada.guard.server.commons.utils.Constant;
import fr.sii.ogham.core.builder.MessagingBuilder;
import fr.sii.ogham.core.service.MessagingService;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

public class MailManager extends AbstractVerticle {

    private static final Logger LOGGER = LoggerFactory.getLogger(MailManager.class);

    private EmailConfirmation emailConfirmation;
    private PasswordReset passwordReset;

    @Override
    public void start(Future<Void> startFuture) {
        Properties properties = new Properties();
        properties.setProperty("mail.smtp.host", config().getString(Constant.SMTP_SERVER_HOST, "smtp.mailtrap.io"));
        properties.setProperty("mail.smtp.port", String.valueOf(config().getInteger(Constant.SMTP_SERVER_PORT, 465)));
        properties.setProperty("ogham.email.from", config().getString(Constant.SMTP_FROM, Constant.DO_NOT_REPLY_EMAIL));
        MessagingService messagingService = MessagingBuilder.standard()
                .environment()
                .properties(properties)
                .and()
                .build();

        this.emailConfirmation = new EmailConfirmation(vertx, messagingService);
        this.passwordReset = new PasswordReset(vertx, messagingService);

        vertx.eventBus().consumer(Constant.MAIL_MANAGER_QUEUE, this::onMessage);
        LOGGER.info(String.format("Guard Mail manager %s is up and running", this.toString().split("@")[1]));
        startFuture.complete();
    }

    private void onMessage(Message<JsonObject> message) {
        if (!message.headers().contains(Constant.ACTION)) {
            message.fail(ErrorCodes.NO_ACTION_SPECIFIED.ordinal(), "No action header specified");
        }
        String action = message.headers().get(Constant.ACTION);

        switch (action) {
            case Constant.ACTION_EMAIL_CONFIRMATION_REQUEST:
                this.emailConfirmation.sendConfirmationRequest(message);
                break;

            case Constant.ACTION_EMAIL_CONFIRMATION_RESULT:
                this.emailConfirmation.sendConfirmationResult(message);
                break;

            case Constant.ACTION_EMAIL_PASS_RESET_REQUEST_OK:
               this.passwordReset.sendResetRequestOk(message);
                break;

            case Constant.ACTION_EMAIL_PASS_RESET_REQUEST_KO:
                this.passwordReset.sendResetRequestKo(message);
                break;

            case Constant.ACTION_EMAIL_PASS_RESET_RESULT:
                this.passwordReset.sendResetResult(message);
                break;

            default:
                message.fail(ErrorCodes.BAD_ACTION.ordinal(), "Bad action: " + action);
        }

    }
}
