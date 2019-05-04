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


import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.policies.DCAwareRoundRobinPolicy;
import io.vertx.core.json.JsonObject;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class CassandraDriver {
    private static CassandraDriver instance = null;
    private Cluster cluster;

    public static CassandraDriver getOrCreate(JsonObject config) {
        if (Objects.isNull(CassandraDriver.instance)) {
            synchronized (CassandraDriver.class) {
                if (Objects.isNull(CassandraDriver.instance)) {
                    CassandraDriver.instance = new CassandraDriver(config);
                    GuardMetricsReporter reporter = new GuardMetricsReporter("guard-cassandra-client", CassandraDriver.instance.cluster.getMetrics().getRegistry());
                    reporter.start(1, TimeUnit.MINUTES);
                }
            }
        }
        return CassandraDriver.instance;
    }

    private CassandraDriver(JsonObject config) {
        Cluster.Builder clusterBuilder = Cluster.builder()
                .withClusterName(Constant.DRIVER_CASSANDRA_CLUSTER_NAME)
                .withoutJMXReporting()
                .addContactPoints(config.getString(Constant.CASSANDRA_CLUSTER_CONFIG_KEY, Constant.DEFAULT_CASSANDRA_CLUSTER).split(","))
                .withPort(config.getInteger(Constant.CASSANDRA_CLUSTER_PORT_KEY, Constant.DEFAULT_CASSANDRA_PORT))
                .withLoadBalancingPolicy(
                        DCAwareRoundRobinPolicy.builder()
                                .withLocalDc(config.getString(Constant.CASSANDRA_DATACENTER_CONFIG_KEY, Constant.DEFAULT_CASSANDRA_DATACENTER))
                                .withUsedHostsPerRemoteDc(2)
                                .allowRemoteDCsForLocalConsistencyLevel()
                                .build()
                );
        if (config.getBoolean(Constant.CASSANDRA_CLUSTER_SSL_CONFIG_KEY, false)) {
            clusterBuilder.withSSL();
        }
        this.cluster = clusterBuilder.build();
        this.cluster.init();
    }

    public Cluster getCluster() {
        return this.cluster;
    }
}
