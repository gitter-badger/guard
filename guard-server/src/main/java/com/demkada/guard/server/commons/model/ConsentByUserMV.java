package com.demkada.guard.server.commons.model;

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
import info.archinnov.achilles.annotations.ClusteringColumn;
import info.archinnov.achilles.annotations.Column;
import info.archinnov.achilles.annotations.MaterializedView;
import info.archinnov.achilles.annotations.PartitionKey;

import java.util.Date;

@MaterializedView(baseEntity = Consent.class, keyspace = Constant.GUARD,view = Constant.CONSENTS_BY_USER)
public class ConsentByUserMV {

    @PartitionKey
    @Column(Constant.USER_EMAIL)
    private String userEmail;

    @ClusteringColumn()
    @Column(Constant.SCOPE_NAME)
    private String scopeName;


    @ClusteringColumn(value = 2)
    @Column(Constant.CLIENT_ID)
    private String clientId;

    @Column(Constant.TIMESTAMP)
    private Date timestamp;

    @Column(Constant.CLIENT_NAME)
    private String clientName;

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getScopeName() {
        return scopeName;
    }

    public void setScopeName(String scopeName) {
        this.scopeName = scopeName;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }
}
