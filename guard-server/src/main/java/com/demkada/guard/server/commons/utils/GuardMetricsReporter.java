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


import com.codahale.metrics.*;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.Map;
import java.util.SortedMap;
import java.util.concurrent.TimeUnit;

public class GuardMetricsReporter  extends ScheduledReporter {

    private static final Logger LOGGER = LoggerFactory.getLogger(GuardMetricsReporter.class);

    public GuardMetricsReporter(String name, MetricRegistry registry) {
        super(registry, name, MetricFilter.ALL, TimeUnit.SECONDS, TimeUnit.SECONDS);
    }

    public void report(SortedMap<String, Gauge> gauges,
                       SortedMap<String, Counter> counters,
                       SortedMap<String, Histogram> histograms,
                       SortedMap<String, Meter> meters,
                       SortedMap<String, Timer> timers) {
        final String metricType = "metric_type";
        for (Map.Entry<String, Gauge> entry : gauges.entrySet()) {
            MDC.put(metricType, "GAUGE");
            log(entry);
            MDC.remove(metricType);
        }

        for (Map.Entry<String, Counter> entry : counters.entrySet()) {
            MDC.put(metricType, "COUNTER");
            log(entry);
            MDC.remove(metricType);
        }

        for (Map.Entry<String, Histogram> entry : histograms.entrySet()) {
            MDC.put(metricType, "HISTOGRAM");
            log(entry);
            MDC.remove(metricType);
        }

        for (Map.Entry<String, Meter> entry : meters.entrySet()) {
            MDC.put(metricType, "METER");
            log(entry);
            MDC.remove(metricType);
        }

        for (Map.Entry<String, Timer> entry : timers.entrySet()) {
            MDC.put(metricType, "TIMER");
            log(entry);
            MDC.remove(metricType);
        }
    }

    private void log(Object entry) {
        if (LOGGER.isInfoEnabled()) {
            MDC.put("type", "METRIC");
            LOGGER.info(JsonObject.mapFrom(entry).encode());
            MDC.remove("type");
        }
    }

}
