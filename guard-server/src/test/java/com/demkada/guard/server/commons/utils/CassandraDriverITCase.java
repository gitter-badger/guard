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


import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.ManagerFactory_For_Guard;
import info.archinnov.achilles.junit.AchillesTestResource;
import info.archinnov.achilles.junit.AchillesTestResourceBuilder;
import io.vertx.core.Vertx;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.*;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class CassandraDriverITCase {

    private Vertx vertx;

    @Before
    public void setUp() {
        vertx = Vertx.vertx();
    }

    @Rule
    public AchillesTestResource<ManagerFactory_For_Guard> resource =  AchillesTestResourceBuilder
            .forJunit()
            .truncateBeforeAndAfterTest()
            .build((cluster, statementsCache) -> ManagerFactoryBuilder_For_Guard
                    .builder(cluster)
                    .doForceSchemaCreation(true)
                    .withDefaultKeyspaceName(Constant.GUARD)
                    .build()
            );

    @Test
    public void shouldInitCluster() {
        Assert.assertNotNull(resource.getNativeSession());
    }

    @Test
    public void shouldInitGuardKeySpace() {
        Assert.assertTrue(
                resource.getNativeSession().getCluster().getMetadata().getKeyspaces()
                        .stream().anyMatch(keyspaceMetadata -> keyspaceMetadata.getName().equalsIgnoreCase(Constant.GUARD))
        );
    }

    @After
    public void tearDown(TestContext tc) {
        vertx.close(tc.asyncAssertSuccess());
    }
}