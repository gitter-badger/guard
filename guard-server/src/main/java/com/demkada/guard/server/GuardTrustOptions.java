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


import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.vertx.core.Vertx;
import io.vertx.core.net.TrustOptions;

import javax.net.ssl.TrustManagerFactory;

public class GuardTrustOptions implements TrustOptions {

    @Override
    public TrustOptions clone() {
        return new GuardTrustOptions();
    }

    @Override
    public TrustManagerFactory getTrustManagerFactory(Vertx vertx) throws Exception {
        return InsecureTrustManagerFactory.INSTANCE;
    }

}

