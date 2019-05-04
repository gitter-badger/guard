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


import io.vertx.core.Vertx;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class StringHashUtilTest {

    private Vertx vertx = Vertx.vertx();
    private final String password = "myPassword";
    private final String hash = "1000:f4bda962299157be53020de9ef093313:05b87030fb696e7c79137aafc7a690ef733e6e33e12655a25196995ae25628149046a267d74388c2b6a29ebc4f7a075d42aa3689f279f9b480addcb21664dd5d";



    @Test
    public void shouldGenerateAPasswordHash(TestContext testContext) {
        Async async = testContext.async();

        StringHashUtil.generateHash(vertx, password, ar -> {
            testContext.assertTrue(ar.succeeded());
            testContext.assertEquals(ar.result().split(":").length, 3);
            async.complete();
        });
    }

    @Test
    public void shouldnotHashNullValue(TestContext testContext) {
        Async async = testContext.async();
        StringHashUtil.generateHash(vertx, null, ar -> {
            testContext.assertTrue(ar.failed());
            async.complete();
        });
    }

    @Test
    public void shouldnotHashEmptyValue(TestContext testContext) {
        Async async = testContext.async();
        StringHashUtil.generateHash(vertx,"", ar -> {
            testContext.assertTrue(ar.failed());
            async.complete();
        });
    }

    @Test
    public void shouldValidateAGeneratedPassword(TestContext testContext) {
        Async async = testContext.async();

        StringHashUtil.validatePassword(vertx, password, hash, ar -> {
            testContext.assertTrue(ar.succeeded());
            testContext.assertTrue(ar.result());
            async.complete();
        });
    }

    @Test
    public void shouldNotValidateABadPassword(TestContext testContext) {
        Async async = testContext.async();
        String password = "myPassword1";
        StringHashUtil.validatePassword(vertx, password, hash, ar -> {
            testContext.assertTrue(ar.succeeded());
            testContext.assertFalse(ar.result());
            async.complete();
        });
    }

    @After
    public void tearDown(TestContext tc) {
        vertx.close(tc.asyncAssertSuccess());
    }
}