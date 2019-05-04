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


import com.demkada.guard.server.commons.model.ErrorCodes;
import com.demkada.guard.server.commons.model.QuestionId;
import com.demkada.guard.server.commons.model.User;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.VertxContextPRNG;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.*;

class DataCipher {

    private static final Logger LOGGER = LoggerFactory.getLogger(DataCipher.class);

    private final Vertx vertx;
    private final Key dataCipherKey;
    private Cipher primaryKeyCipher;
    private Cipher primaryKeyDecipher;

    private static final String PRIMARY_KEY_CIPHER_INSTANCE = "AES/CBC/PKCS5Padding";
    private static final String GENERIC_CIPHER_INSTANCE = "AES/GCM/NoPadding";

    DataCipher(Vertx vertx, Key primaryKeyCipherKey, Key dataCipherKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        this.vertx = vertx;
        this.dataCipherKey = dataCipherKey;
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        primaryKeyCipher = Cipher.getInstance(PRIMARY_KEY_CIPHER_INSTANCE);
        primaryKeyCipher.init(Cipher.ENCRYPT_MODE, primaryKeyCipherKey, ivspec);

        primaryKeyDecipher = Cipher.getInstance(PRIMARY_KEY_CIPHER_INSTANCE);
        primaryKeyDecipher.init(Cipher.DECRYPT_MODE, primaryKeyCipherKey, ivspec);
    }

    void encryptPk(Message<JsonObject> message) {
        vertx.<String>executeBlocking(f -> {
            try {
                String plain = message.body().getString(Constant.PAYLOAD);
                f.complete(Base64.getEncoder().encodeToString(primaryKeyCipher.doFinal(plain.getBytes())));
            } catch (Exception e) {
                f.fail(new GuardException(e));
            }
        }, r -> {
            if (r.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, r.result()));
            }
            else {
                LOGGER.error("Unable to encrypt Primary Key", r.cause());
                message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

    void decryptPk(Message<JsonObject> message) {
        String cipherText = message.body().getString(Constant.PAYLOAD);
        vertx.<String>executeBlocking(f -> {
            try {
                f.complete(new String(primaryKeyDecipher.doFinal(Base64.getDecoder().decode(cipherText))));
            } catch (Exception e) {
                f.fail(new GuardException(e));
            }
        }, r -> {
            if (r.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, r.result()));
            }
            else {
                LOGGER.error("Unable to decrypt Primary Key", r.cause());
                message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

    void encryptSet(Message<JsonObject> message) {
        vertx.<JsonArray>executeBlocking(f -> {
            try {
                JsonArray plain = message.body().getJsonArray(Constant.PAYLOAD);
                JsonArray cipher = new JsonArray();
                plain.forEach(s -> cipher.add(encryptString((String) s)));
                f.complete(cipher);
            } catch (Exception e) {
                f.fail(new GuardException(e));
            }
        }, r -> {
            if (r.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, r.result()));
            }
            else {
                LOGGER.error("Unable to encrypt String Set", r.cause());
                message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

    void decryptSet(Message<JsonObject> message) {
        JsonArray cipher = message.body().getJsonArray(Constant.PAYLOAD);
        JsonArray plain = new JsonArray();
        vertx.<JsonArray>executeBlocking(f -> {
            try {
                cipher.forEach(s -> plain.add(decryptString((String) s)));
                f.complete(plain);
            } catch (Exception e) {
                f.fail(new GuardException(e));
            }
        }, r -> {
            if (r.succeeded()) {
                message.reply(new JsonObject().put(Constant.RESPONSE, r.result()));
            }
            else {
                LOGGER.error("Unable to encrypt String Set", r.cause());
                message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), r.cause().getMessage());
            }
        });
    }

    void encryptUserPii(Message<JsonObject> message) {
        vertx.<JsonArray>executeBlocking(f -> {
            try {
                JsonArray users = message.body().getJsonArray(Constant.PAYLOAD);
                JsonArray cipheredUsers = new JsonArray();
                users.forEach(u -> {
                    User user = ((JsonObject) u).mapTo(User.class);
                    User cipheredUser = new User();

                    if (Objects.nonNull(user.getEmail())) {
                        try {
                            cipheredUser.setEmail(Base64.getEncoder().encodeToString(primaryKeyCipher.doFinal(user.getEmail().toLowerCase().getBytes())));
                        } catch (Exception e) {
                            LOGGER.error("Unable to encrypt primary key", new GuardException(e));
                            cipheredUser.setEmail(user.getEmail());
                        }
                    }

                    gcmEncryptUser(user, cipheredUser);
                    cipheredUsers.add(JsonObject.mapFrom(cipheredUser));
                });

                f.complete(cipheredUsers);
            } catch (Exception e) {
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

    void decryptUserPii(Message<JsonObject> message) {

        vertx.<JsonArray>executeBlocking(f -> {
            try {
                JsonArray cipheredUsers = message.body().getJsonArray(Constant.PAYLOAD);
                JsonArray users = new JsonArray();
                cipheredUsers.forEach(u -> {
                    User ciphered = ((JsonObject) u).mapTo(User.class);
                    User user = new User();

                    if (Objects.nonNull(ciphered.getEmail())) {
                        try {
                            user.setEmail(new String(primaryKeyDecipher.doFinal(Base64.getDecoder().decode(ciphered.getEmail()))));
                        } catch (Exception e) {
                            LOGGER.error("Unable to decrypt primary key", new GuardException(e));
                            user.setEmail(ciphered.getEmail());
                        }
                    }
                    gcmDecryptUser(ciphered, user);
                    users.add(JsonObject.mapFrom(user));
                });

                f.complete(users);
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

    private void gcmDecryptUser(User ciphered, User user) {

        user.setPhoneNumberVerified(ciphered.isPhoneNumberVerified());

        user.setEmailVerified(ciphered.isEmailVerified());

        user.setDisable(ciphered.isDisable());

        if (Objects.nonNull(ciphered.getIdOrigin())) {
            user.setIdOrigin(ciphered.getIdOrigin());
        }
        if (Objects.nonNull(ciphered.getPwd())) {
            user.setPwd(ciphered.getPwd());
        }

        if (Objects.nonNull(ciphered.getPin())) {
            String cipherText = ciphered.getPin();
            String plain = decryptString(cipherText);
            user.setPin(plain);
        }

        if (Objects.nonNull(ciphered.getSub())) {
            String cipherText = ciphered.getSub();
            String plain = decryptString(cipherText);
            user.setSub(plain);
        }

        if (Objects.nonNull(ciphered.getGivenName())) {
            String cipherText = ciphered.getGivenName();
            String plain = decryptString(cipherText);
            user.setGivenName(plain);
        }

        if (Objects.nonNull(ciphered.getFamilyName())) {
            String cipherText = ciphered.getFamilyName();
            String plain = decryptString(cipherText);
            user.setFamilyName(plain);
        }

        if (Objects.nonNull(ciphered.getAddress())) {
            String cipherText = ciphered.getAddress();
            String plain = decryptString(cipherText);
            user.setAddress(plain);
        }

        if (Objects.nonNull(ciphered.getPhoneNumber())) {
            String cipherText = ciphered.getPhoneNumber();
            String plain = decryptString(cipherText);
            user.setPhoneNumber(plain);
        }

        if (Objects.nonNull(ciphered.getSecurityQuestion())) {
            Map<QuestionId, String>  secQ = ciphered.getSecurityQuestion();
            Map<QuestionId, String>  decryptedSecQ = new EnumMap<>(QuestionId.class);
            secQ.forEach((k, v) -> {
                String plain = decryptString(v);
                decryptedSecQ.put(k, plain);
            });
            user.setSecurityQuestion(decryptedSecQ);
        }
    }

    private void gcmEncryptUser(User user, User cipheredUser) {
        cipheredUser.setPhoneNumberVerified(user.isPhoneNumberVerified());

        cipheredUser.setEmailVerified(user.isEmailVerified());

        cipheredUser.setDisable(user.isDisable());

        if (Objects.nonNull(user.getIdOrigin())) {
            cipheredUser.setIdOrigin(user.getIdOrigin());
        }

        if (Objects.nonNull(user.getPwd())) {
            cipheredUser.setPwd(user.getPwd());
        }

        if (Objects.nonNull(user.getPin())) {
            String plain = user.getPin();
            String cipherText = encryptString(plain);
            cipheredUser.setPin(cipherText);
        }

        if (Objects.nonNull(user.getSub())) {
            String sub = user.getSub();
            String cipherText = encryptString(sub);
            cipheredUser.setSub(cipherText);
        }

        if (Objects.nonNull(user.getGivenName())) {
            String plain = user.getGivenName();
            String cipherText = encryptString(plain);
            cipheredUser.setGivenName(cipherText);
        }

        if (Objects.nonNull(user.getFamilyName())) {
            String plain = user.getFamilyName();
            String cipherText = encryptString(plain);
            cipheredUser.setFamilyName(cipherText);
        }

        if (Objects.nonNull(user.getAddress())) {
            String plain = user.getAddress();
            String cipherText = encryptString(plain);
            cipheredUser.setAddress(cipherText);
        }

        if (Objects.nonNull(user.getPhoneNumber())) {
            String plain = user.getPhoneNumber();
            String cipherText = encryptString(plain);
            cipheredUser.setPhoneNumber(cipherText);
        }

        if (Objects.nonNull(user.getSecurityQuestion())) {
            Map<QuestionId, String>  secQ = user.getSecurityQuestion();
            Map<QuestionId, String>  encryptedSecQ = new EnumMap<>(QuestionId.class);
            secQ.forEach((k, v) -> {
                String cipherText = encryptString(v);
                encryptedSecQ.put(k, cipherText);
            });
            cipheredUser.setSecurityQuestion(encryptedSecQ);
        }
    }

    private String encryptString(String plaintext)  {
        try {
            final Cipher cipher = Cipher.getInstance(GENERIC_CIPHER_INSTANCE);
            byte[] iv = new byte[12];
            VertxContextPRNG.current(vertx).nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, dataCipherKey, parameterSpec);
            return Base64.getEncoder().encodeToString(iv) + "." + Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes()));
        } catch (Exception e) {
            LOGGER.error("Unable to encrypt plaintext", new GuardException(e));
        }
        return plaintext;
    }

    private String decryptString(String cipherText) {
        String[] tokens = cipherText.split("\\.");
        try {
            final Cipher cipher = Cipher.getInstance(GENERIC_CIPHER_INSTANCE);
            byte[] iv = Base64.getDecoder().decode(tokens[0]);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, dataCipherKey, parameterSpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(tokens[1])));
        } catch (Exception e) {
            LOGGER.error("Unable to decrypt cipher", new GuardException(e));
        }
        return cipherText;
    }

}
