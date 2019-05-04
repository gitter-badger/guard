package com.demkada.guard.server.crypto;

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


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.model.ErrorCodes;
import com.demkada.guard.server.commons.utils.GuardException;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

class Jwe {

    private static final Logger LOGGER = LoggerFactory.getLogger(Jwe.class);

    private final JWEEncrypter encrypter;
    private final JWEDecrypter decrypter;
    private final Vertx vertx;

    Jwe(Vertx vertx, KeyPair keyPair) {
        this.vertx = vertx;
        this.encrypter = new RSAEncrypter((RSAPublicKey) keyPair.getPublic());
        this.decrypter = new RSADecrypter(keyPair.getPrivate());
    }

    void decryptString(Message<JsonObject> message) {
        vertx.<String>executeBlocking(f -> {
            try {
                String payload = message.body().getString(Constant.PAYLOAD);
                JWEObject jweObject = JWEObject.parse(payload);
                jweObject.decrypt(this.decrypter);
                f.complete(jweObject.getPayload().toString());
            } catch (Exception e) {
                f.fail(new GuardException(e));
            }
        }, r -> {
            if (r.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, r.result()));
            }
            else {
                LOGGER.error("Unable to decrypt String", r.cause());
                message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

    void encryptString(Message<JsonObject> message) {
        vertx.<String>executeBlocking(f -> {
            try {
                String payload = message.body().getString(Constant.PAYLOAD);
                JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
                Payload p = new Payload(payload);
                JWEObject jweObject = new JWEObject(header, p);
                jweObject.encrypt(this.encrypter);
                f.complete(jweObject.serialize());
            } catch (JOSEException e) {
                f.fail(new GuardException(e));
            }
        }, r -> {
            if (r.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, r.result()));
            }
            else {
                LOGGER.error("Unable to encrypt String", r.cause());
                message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

}
