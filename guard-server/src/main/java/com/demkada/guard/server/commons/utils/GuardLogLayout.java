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


import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.contrib.json.classic.JsonLayout;
import io.vertx.core.json.JsonObject;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.Objects;

public class GuardLogLayout extends JsonLayout {

    @SuppressWarnings("unchecked")
    @Override
    protected Map toJsonMap(ILoggingEvent event) {
        Map map = super.toJsonMap(event);
        map.remove(MDC_ATTR_NAME);
        map.remove(FORMATTED_MESSAGE_ATTR_NAME);
        try {
            map.put("content", new JsonObject(event.getFormattedMessage()));
        }
         catch (Exception e) {
             map.put("content", event.getFormattedMessage());
         }
        event.getMDCPropertyMap().forEach(map::put);
        if (!map.containsKey("type")) {
            map.put(Constant.TYPE, "LOG");
        }
        final String source = "source";
        if (Objects.nonNull(System.getenv("GUARD_INSTANCE_NAME"))) {
            map.put(source, System.getenv("GUARD_INSTANCE_NAME"));
        }
        if (!map.containsKey(source)){
            try {
                map.put(source, InetAddress.getLocalHost().getCanonicalHostName());
            } catch (UnknownHostException e) {
                return map;
            }
        }

        return  map;
    }
}
