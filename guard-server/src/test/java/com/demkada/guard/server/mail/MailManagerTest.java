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
import com.demkada.guard.server.commons.model.User;
import com.demkada.guard.server.commons.utils.Constant;
import com.icegreen.greenmail.junit.GreenMailRule;
import com.icegreen.greenmail.util.ServerSetupTest;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;

import static fr.sii.ogham.assertion.OghamAssertions.*;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.Matchers.emptyIterable;
import static org.hamcrest.core.Is.is;

@RunWith(VertxUnitRunner.class)
public class MailManagerTest {

    private Vertx vertx;
    private User user;

    @Rule
    public final GreenMailRule greenMail = new GreenMailRule(ServerSetupTest.SMTP);

    @Before
    public void setUp(TestContext testContext) {
        user = new User();
        user.setEmail("kad.d@demkada.com");
        user.setSub("12345");
        user.setIdOrigin(Constant.GUARD);
        user.setPwd("toto");
        user.setAddress("Paris");
        user.setPhoneNumber("0000");
        user.setGivenName("Kad");
        user.setFamilyName("D.");
        vertx = Vertx.vertx();
        vertx.deployVerticle(
                MailManager.class.getName(),
                new DeploymentOptions().setConfig(
                        new JsonObject()
                                .put(Constant.SMTP_SERVER_HOST, ServerSetupTest.SMTP.getBindAddress())
                                .put(Constant.SMTP_SERVER_PORT, ServerSetupTest.SMTP.getPort())
                ),
                testContext.asyncAssertSuccess());
    }

    @After
    public void tearDown(TestContext testContext) {
        vertx.close(testContext.asyncAssertSuccess());
    }

    @Test
    public void shouldSendEmailConfirmationRequestInEnglish(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_CONFIRMATION_REQUEST);
        EmailInput input = new EmailInput(user, "http://guard.com/12345", "contact@guard.com", "en");
        input.setTitle(Constant.DEFAULT_CONFIRM_ACCOUNT_EMAIL_TITLE_EN);
        JsonObject entries = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(input));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertEquals("done", response.getString("response"));
            testContext.verify(v -> {
                try {
                    assertThat(greenMail).receivedMessages()
                            .count(is(2))
                            .message(0)
                            .subject(is("Confirm your Guard account"))
                            .from()
                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                            .to()
                            .address(hasItems("kad.d@demkada.com")).and()
                            .body()
                            .contentAsString(isSimilarHtml(resourceAsString("template/email/en/test-email-confirmation-request.html")))
                            .contentType(startsWith("text/html")).and()
                            .alternative(nullValue())
                            .attachments(emptyIterable());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                async.complete();
            });
        });
    }

    @Test
    public void shouldSendEmailConfirmationRequestInFrench(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_CONFIRMATION_REQUEST);
        EmailInput input = new EmailInput(user, "http://guard.com/12345", "contact@guard.com", "fr");
        input.setTitle(Constant.DEFAULT_CONFIRM_ACCOUNT_EMAIL_TITLE_FR);
        JsonObject entries = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(
                input
        ));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertEquals("done", response.getString("response"));
            testContext.verify(v -> {
                try {
                    assertThat(greenMail).receivedMessages()
                            .count(is(2))
                            .message(0)
                            .subject(is("Confirmez votre compte Guard"))
                            .from()
                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                            .to()
                            .address(hasItems("kad.d@demkada.com")).and()
                            .body()
                            .contentAsString(isSimilarHtml(resourceAsString("template/email/fr/test-email-confirmation-request.html")))
                            .contentType(startsWith("text/html")).and()
                            .alternative(nullValue())
                            .attachments(emptyIterable());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                async.complete();
            });
        });
    }

    @Test
    public void shouldSendEmailConfirmationResultInEnglish(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_CONFIRMATION_RESULT);
        EmailInput input = new EmailInput(user, "contact@guard.com");

        input.setLocale(Constant.LOCALE_EN);
        input.setTitle(Constant.DEFAULT_VERIFIED_ACCOUNT_EMAIL_TITLE_EN);

        JsonObject entries = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(
                input
        ));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertEquals("done", response.getString("response"));
            testContext.verify(v -> {
                try {
                    assertThat(greenMail).receivedMessages()
                            .count(is(2))
                            .message(0)
                            .subject(is("Your Guard account has been verified"))
                            .from()
                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                            .to()
                            .address(hasItems("kad.d@demkada.com")).and()
                            .body()
                            .contentAsString(isSimilarHtml(resourceAsString("template/email/en/test-email-confirmation-result.html")))
                            .contentType(startsWith("text/html")).and()
                            .alternative(nullValue())
                            .attachments(emptyIterable());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                async.complete();
            });
        });
    }

    @Test
    public void shouldSendEmailConfirmationResultInFrench(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_CONFIRMATION_RESULT);
        EmailInput input = new EmailInput(user, "contact@guard.com");

        input.setLocale(Constant.LOCALE_FR);
        input.setTitle(Constant.DEFAULT_VERIFIED_ACCOUNT_EMAIL_TITLE_FR);
        JsonObject entries = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(
                input
        ));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertEquals("done", response.getString("response"));
            testContext.verify(v -> {
                try {
                    assertThat(greenMail).receivedMessages()
                            .count(is(2))
                            .message(0)
                            .subject(is("Votre compte Guard a bien été vérifié"))
                            .from()
                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                            .to()
                            .address(hasItems("kad.d@demkada.com")).and()
                            .body()
                            .contentAsString(isSimilarHtml(resourceAsString("template/email/fr/test-email-confirmation-result.html")))
                            .contentType(startsWith("text/html")).and()
                            .alternative(nullValue())
                            .attachments(emptyIterable());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                async.complete();
            });
        });
    }

    @Test
    public void shouldSendPasswordResetRequestOkInEnglish(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_PASS_RESET_REQUEST_OK);
        EmailInput input = new EmailInput(user, "http://guard.com/12345", "contact@guard.com", "en");
        input.setTitle(Constant.DEFAULT_RESET_PASS_REQUEST_EMAIL_TITLE_EN);
        JsonObject entries = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(
                input
        ));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertEquals("done", response.getString("response"));
            testContext.verify(v -> {
                try {
                    assertThat(greenMail).receivedMessages()
                            .count(is(2))
                            .message(0)
                            .subject(is("Your Guard account password reset request"))
                            .from()
                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                            .to()
                            .address(hasItems("kad.d@demkada.com")).and()
                            .body()
                            .contentAsString(isSimilarHtml(resourceAsString("template/email/en/test-password-reset-request-ok.html")))
                            .contentType(startsWith("text/html")).and()
                            .alternative(nullValue())
                            .attachments(emptyIterable());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                async.complete();
            });
        });
    }

    @Test
    public void shouldSendPasswordResetRequestOkInFrench(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_PASS_RESET_REQUEST_OK);
        EmailInput input = new EmailInput(user, "http://guard.com/12345", "contact@guard.com", "fr");
        input.setTitle(Constant.DEFAULT_RESET_PASS_REQUEST_EMAIL_TITLE_FR);
        JsonObject entries = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(
                input
        ));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertEquals("done", response.getString("response"));
            testContext.verify(v -> {
                try {
                    assertThat(greenMail).receivedMessages()
                            .count(is(2))
                            .message(0)
                            .subject(is("Demande de réinitialisation de votre mot de passe Guard"))
                            .from()
                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                            .to()
                            .address(hasItems("kad.d@demkada.com")).and()
                            .body()
                            .contentAsString(isSimilarHtml(resourceAsString("template/email/fr/test-password-reset-request-ok.html")))
                            .contentType(startsWith("text/html")).and()
                            .alternative(nullValue())
                            .attachments(emptyIterable());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                async.complete();
            });
        });
    }

    @Test
    public void shouldSendPasswordResetRequestKoInEnglish(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_PASS_RESET_REQUEST_KO);
        EmailInput input = new EmailInput(user, "contact@guard.com");

        input.setLocale(Constant.LOCALE_EN);
        input.setTitle(Constant.DEFAULT_RESET_PASS_REQUEST_EMAIL_TITLE_EN);

        JsonObject entries = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(
                input
        ));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertEquals("done", response.getString("response"));
            testContext.verify(v -> {
                try {
                    assertThat(greenMail).receivedMessages()
                            .count(is(2))
                            .message(0)
                            .subject(is("Your Guard account password reset request"))
                            .from()
                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                            .to()
                            .address(hasItems("kad.d@demkada.com")).and()
                            .body()
                            .contentAsString(isSimilarHtml(resourceAsString("template/email/en/test-password-reset-request-ko.html")))
                            .contentType(startsWith("text/html")).and()
                            .alternative(nullValue())
                            .attachments(emptyIterable());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                async.complete();
            });
        });
    }
    @Test
    public void shouldSendPasswordResetRequestKoInFrench(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_PASS_RESET_REQUEST_KO);
        EmailInput input = new EmailInput(user, "contact@guard.com");
        input.setLocale(Constant.LOCALE_FR);
        input.setTitle(Constant.DEFAULT_RESET_PASS_REQUEST_EMAIL_TITLE_FR);
        JsonObject entries = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(
                input
        ));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertEquals("done", response.getString("response"));
            testContext.verify(v -> {
                try {
                    assertThat(greenMail).receivedMessages()
                            .count(is(2))
                            .message(0)
                            .subject(is("Demande de réinitialisation de votre mot de passe Guard"))
                            .from()
                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                            .to()
                            .address(hasItems("kad.d@demkada.com")).and()
                            .body()
                            .contentAsString(isSimilarHtml(resourceAsString("template/email/fr/test-password-reset-request-ko.html")))
                            .contentType(startsWith("text/html")).and()
                            .alternative(nullValue())
                            .attachments(emptyIterable());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                async.complete();
            });
        });
    }

    @Test
    public void shouldSendPasswordResetResultInEnglish(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_PASS_RESET_RESULT);
        EmailInput input = new EmailInput(user, "contact@guard.com");
        input.setLocale(Constant.LOCALE_EN);
        input.setTitle(Constant.DEFAULT_CHANGE_PASS_SUCCESS_EMAIL_TITLE_EN);
        JsonObject entries = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(
                input
        ));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertEquals("done", response.getString("response"));
            testContext.verify(v -> {
                try {
                    assertThat(greenMail).receivedMessages()
                            .count(is(2))
                            .message(0)
                            .subject(is("You have successfully change your Guard's account password"))
                            .from()
                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                            .to()
                            .address(hasItems("kad.d@demkada.com")).and()
                            .body()
                            .contentAsString(isSimilarHtml(resourceAsString("template/email/en/test-password-reset-result.html")))
                            .contentType(startsWith("text/html")).and()
                            .alternative(nullValue())
                            .attachments(emptyIterable());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                async.complete();
            });
        });
    }

    @Test
    public void shouldSendPasswordResetResultInFrench(TestContext testContext) {
        Async async = testContext.async();
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_EMAIL_PASS_RESET_RESULT);
        EmailInput input = new EmailInput(user, "contact@guard.com");

        input.setLocale(Constant.LOCALE_FR);
        input.setTitle(Constant.DEFAULT_CHANGE_PASS_SUCCESS_EMAIL_TITLE_FR);

        JsonObject entries = new JsonObject().put(Constant.EMAIL_INPUT, JsonObject.mapFrom(
                input
        ));
        this.vertx.eventBus().send(Constant.MAIL_MANAGER_QUEUE, entries, options, res -> {
            testContext.assertTrue(res.succeeded());
            testContext.assertNotNull(res.result().body());
            JsonObject response = (JsonObject) res.result().body();
            testContext.assertEquals("done", response.getString("response"));
            testContext.verify(v -> {
                try {
                    assertThat(greenMail).receivedMessages()
                            .count(is(2))
                            .message(0)
                            .subject(is("Réinitilisation de votre mot de passe Guard réussie"))
                            .from()
                            .address(hasItems(Constant.DO_NOT_REPLY_EMAIL)).and()
                            .to()
                            .address(hasItems("kad.d@demkada.com")).and()
                            .body()
                            .contentAsString(isSimilarHtml(resourceAsString("template/email/fr/test-password-reset-result.html")))
                            .contentType(startsWith("text/html")).and()
                            .alternative(nullValue())
                            .attachments(emptyIterable());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                async.complete();
            });
        });
    }

}