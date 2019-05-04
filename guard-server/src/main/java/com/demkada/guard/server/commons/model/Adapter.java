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


import com.datastax.driver.core.ConsistencyLevel;
import com.demkada.guard.server.commons.utils.Constant;
import info.archinnov.achilles.annotations.*;

@Table(table= Constant.ADAPTERS_BY_ID)
@Consistency(
        read = ConsistencyLevel.LOCAL_QUORUM,
        write = ConsistencyLevel.LOCAL_QUORUM,
        serial = ConsistencyLevel.LOCAL_SERIAL)
public class Adapter {

    @Column(Constant.ID)
    @PartitionKey
    private String id;

    @Column(Constant.NAME)
    private String name;

    @Column(Constant.DESCRIPTION)
    private String description;

    @Column(Constant.LOGO_URL)
    private String logoUrl;

    @Column(Constant.TRIGGER_ON_HOSTNAME)
    private String triggerOnHostname;

    @Column(Constant.TYPE)
    @Enumerated(Enumerated.Encoding.NAME)
    private AdapterType type;

    @Column(Constant.ADAPTER_URL)
    private String adapterUrl;

    @Column(Constant.CLIENT_ID)
    private String clientId;

    @Column(Constant.PUBLIC_KEY)
    private String publicKey;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getLogoUrl() {
        return logoUrl;
    }

    public void setLogoUrl(String logoUrl) {
        this.logoUrl = logoUrl;
    }

    public String getTriggerOnHostname() {
        return triggerOnHostname;
    }

    public void setTriggerOnHostname(String triggerOnHostname) {
        this.triggerOnHostname = triggerOnHostname;
    }

    public AdapterType getType() {
        return type;
    }

    public void setType(AdapterType type) {
        this.type = type;
    }

    public String getAdapterUrl() {
        return adapterUrl;
    }

    public void setAdapterUrl(String adapterUrl) {
        this.adapterUrl = adapterUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
