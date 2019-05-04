package com.demkada.guard.server;

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


import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.PfxOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class HttpServer extends AbstractVerticle {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpServer.class);
    @Override
    public void start(Future<Void> startFuture) {
        PfxOptions pfxOptions;
        try {
            pfxOptions = new PfxOptions()
                    .setPassword(config().getString(Constant.GUARD_HTTPS_P12PASS_CONFIG_KEY, "D-Guard"));
            if (config().containsKey(Constant.GUARD_HTTPS_P12PATH_CONFIG_KEY)) {
                pfxOptions.setPath(config().getString(Constant.GUARD_HTTPS_P12PATH_CONFIG_KEY));
            } else {
                pfxOptions.setValue(
                        Buffer.buffer(Utils.convertToByteArray(
                                vertx.getClass().getClassLoader().getResourceAsStream("guard-tls-server.p12")))
                );
            }

            io.vertx.core.http.HttpServer guardHttpsServer = vertx.createHttpServer(new HttpServerOptions()
                    .setSsl(true)
                    .setPfxKeyCertOptions(pfxOptions)
                    .setTrustOptions(new GuardTrustOptions())
            );

            guardHttpsServer
                    .requestHandler(new Router(vertx).getInstance()::accept)
                    .listen(config().getInteger(Constant.GUARD_HTTPS_PORT_CONFIG_KEY, 8443),
                            asyncResult -> {
                                if (asyncResult.succeeded()) {
                                    LOGGER.info(String.format("Guard http server %s is listening on port: %d", this.toString().split("@")[1], asyncResult.result().actualPort()));
                                    startFuture.complete();

                                } else {
                                    LOGGER.error(String.format("Error when trying to start Guard http server: %s", asyncResult.cause()));
                                    startFuture.fail(asyncResult.cause());
                                }
                            }
                    );
        } catch (IOException e) {
            LOGGER.error(String.format("Error when trying to start Guard http server: %s", e.getCause()));
            startFuture.fail(e);
        }
    }
}
