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
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import fr.sii.ogham.core.message.content.TemplateContent;
import fr.sii.ogham.core.service.MessagingService;
import fr.sii.ogham.email.message.Email;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class MailService {

    private static final Logger LOGGER = LoggerFactory.getLogger(MailService.class);

    private final MessagingService service;
    private final Vertx vertx;

    MailService(Vertx vertx, MessagingService service) {
        this.vertx = vertx;
        this.service = service;
    }

    void sendSimpleEmail(EmailInput emailInput, String template, Handler<AsyncResult<Void>> handler) {
        Future<Void> f = Future.future();
        try {
            String templatePath;
            if (vertx.getOrCreateContext().config().containsKey(Constant.GUARD_EMAIL_TEMPLATE_DIRECTORY)) {
                templatePath = "file:/" + vertx.getOrCreateContext().config().getString(Constant.GUARD_EMAIL_TEMPLATE_DIRECTORY);
            }
            else {
                templatePath = Constant.TEMPLATE_PATH_PREFIX;
            }
            service.send(new Email()
                    .subject(emailInput.getTitle())
                    .content(new TemplateContent( templatePath + template, emailInput))
                    .to(emailInput.getUser().getEmail())
                    .bcc(emailInput.getContact())
            );
            f.complete();
        }
        catch (Exception e) {
            LOGGER.error("Impossible to send email", new GuardException(e));
            f.fail(e);
        }
        f.setHandler(handler);
    }
}
