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


import com.codahale.metrics.SharedMetricRegistries;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardMetricsReporter;
import com.demkada.guard.server.commons.utils.Utils;
import io.vertx.core.Launcher;
import io.vertx.core.VertxOptions;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.eventbus.EventBusOptions;
import io.vertx.core.http.ClientAuth;
import io.vertx.core.net.PfxOptions;
import io.vertx.ext.dropwizard.DropwizardMetricsOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class GuardLauncher extends Launcher {

    private static final Logger LOGGER = LoggerFactory.getLogger(GuardLauncher.class);

    public static void main(String[] args) {
        System.setProperty("vertx.cacheDirBase","./.guard");
        System.setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.SLF4JLogDelegateFactory");
        System.setProperty("vertx.hazelcast.config", "guard-hazelcast.xml");
        System.setProperty("hazelcast.logging.type", "slf4j");
        System.setProperty("org.jboss.logging.provider","slf4j");

        new GuardLauncher().dispatch(args);
    }

    @Override
    public void beforeStartingVertx(VertxOptions options) {
        PfxOptions pfxOptions = new PfxOptions();
        try {
            pfxOptions.setPassword(System.getProperty(Constant.GUARD_EB_P12PASS_CONFIG_KEY, "D-Guard"));
            if (Objects.nonNull(System.getProperty(Constant.GUARD_EB_P12PATH_CONFIG_KEY))) {
                pfxOptions.setPath(System.getProperty(Constant.GUARD_EB_P12PATH_CONFIG_KEY));
            }
            else {
                pfxOptions.setValue(
                        Buffer.buffer(Utils.convertToByteArray(getClass().getClassLoader().getResourceAsStream("guard-tls-server.p12")))
                );
            }

            options.setEventBusOptions(
                    new EventBusOptions()
                            .setClustered(true)
                            .setSsl(true)
                            .setClientAuth(ClientAuth.REQUIRED)
                            .setPfxKeyCertOptions(pfxOptions)
            );

            options.setMetricsOptions(
                    new DropwizardMetricsOptions()
                            .setBaseName(Constant.GUARD)
                            .setRegistryName(Constant.GUARD)
                            .setJmxEnabled(true)
                            .setJmxDomain(Constant.GUARD)
                            .setEnabled(true)
            );

            final GuardMetricsReporter reporter = new GuardMetricsReporter("guard-server", SharedMetricRegistries.getOrCreate(Constant.GUARD));
            reporter.start(1, TimeUnit.MINUTES);
        }
        catch (IOException e) {
            LOGGER.error("Can't encrypt Guard cluster event bus", e);
        }
    }
}
