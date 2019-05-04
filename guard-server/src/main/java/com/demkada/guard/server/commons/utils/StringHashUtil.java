package com.demkada.guard.server.commons.utils;

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


import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

public class StringHashUtil {

    private StringHashUtil() {
        // Hide public one
    }

    public static void generateHash(Vertx vertx, String password, Handler<AsyncResult<String>> handler) {
        Future<String> future = Future.future();
        if (Objects.isNull(password) || password.isEmpty()) {
            future.fail("Nothing to hash");
        }
        else {
            vertx.<String>executeBlocking(f -> {
                try {
                    int iterations = 1000;
                    char[] chars = password.toCharArray();
                    byte[] salt = generateSalt();
                    PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
                    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                    byte[] hash = skf.generateSecret(spec).getEncoded();
                    f.complete(iterations + ":" + byteArrayToHex(salt) + ":" + byteArrayToHex(hash));
                }
                catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    f.fail(new GuardException(e));
                }
            }, ar -> {
                if (ar.succeeded()) {
                    future.complete(ar.result());
                }
                else {
                    future.fail(ar.cause());
                }
            });
        }
        future.setHandler(handler);
    }

    public static void validatePassword(Vertx vertx, String actualPassword, String storedPassword, Handler<AsyncResult<Boolean>> handler) {
        Future<Boolean> future = Future.future();
        vertx.<Boolean>executeBlocking(f -> {
            try {
                String[] parts = storedPassword.split(":");
                int iterations = Integer.parseInt(parts[0]);
                byte[] salt = hexToByteArray(parts[1]);
                byte[] hash = hexToByteArray(parts[2]);

                PBEKeySpec spec = new PBEKeySpec(actualPassword.toCharArray(), salt, iterations, hash.length * 8);
                SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                byte[] testHash = skf.generateSecret(spec).getEncoded();

                int diff = hash.length ^ testHash.length;
                for(int i = 0; i < hash.length && i < testHash.length; i++) {
                    diff |= hash[i] ^ testHash[i];
                }
                f.complete(diff == 0);
            }
            catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                f.fail(new GuardException(e));
            }
        }, ar -> {
            if (ar.succeeded()) {
                future.complete(ar.result());
            }
            else {
                future.fail(ar.cause());
            }
        });
        future.setHandler(handler);
    }

    private static byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    private static String byteArrayToHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0) {
            return String.format(String.format("%%0%dd", paddingLength), 0) + hex;
        }
        else{
            return hex;
        }
    }

    private static byte[] hexToByteArray(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i<bytes.length ;i++)
        {
            bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }
}
