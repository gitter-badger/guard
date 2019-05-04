package com.demkada.guard.server.commons;

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
import info.archinnov.achilles.annotations.CompileTimeConfig;
import info.archinnov.achilles.type.CassandraVersion;
import info.archinnov.achilles.type.strategy.ColumnMappingStrategy;
import info.archinnov.achilles.type.strategy.InsertStrategy;
import info.archinnov.achilles.type.strategy.NamingStrategy;

@CompileTimeConfig(
        projectName = Constant.GUARD,
        cassandraVersion = CassandraVersion.CASSANDRA_3_11_0,
        columnMappingStrategy = ColumnMappingStrategy.EXPLICIT,
        namingStrategy = NamingStrategy.SNAKE_CASE,
        insertStrategy = InsertStrategy.NOT_NULL_FIELDS
)
public interface AchillesConfig {
}
