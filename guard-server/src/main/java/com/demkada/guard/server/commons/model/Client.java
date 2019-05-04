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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Table(table= Constant.CLIENTS_BY_ID)
@Consistency(
        read = ConsistencyLevel.LOCAL_QUORUM,
        write = ConsistencyLevel.LOCAL_QUORUM,
        serial = ConsistencyLevel.LOCAL_SERIAL)
public class Client {

    @Column(Constant.CLIENT_ID)
    @PartitionKey
    private String id;

    @Column(Constant.CLIENT_NAME)
    private String name;

    @Column(Constant.CLIENT_SECRET)
    private String secret;

    @Column(Constant.CLIENT_TYPE)
    @Enumerated(Enumerated.Encoding.NAME)
    private ClientType clientType;

    @Column(Constant.CLIENT_DESCRIPTION)
    private String description;

    @Column(Constant.CLIENT_REDIRECT_URIS)
    private Set<String> redirectUris = new HashSet<>();

    @Column(Constant.CERT)
    private String cert;

    @Column(Constant.CERT_SUBJECT_DN)
    private String certSubjectDn;

    @Column(Constant.CLIENT_MANAGERS)
    private Set<String> managers = new HashSet<>();

    @Column(Constant.CLIENT_LABELS)
    private Map<String, String> labels = new HashMap<>();

    @Column(Constant.CLIENT_ACCESS_POLICIES)
    private Set<String> accessPolicies = new HashSet<>();

    @Column(Constant.DISABLE)
    private boolean disable;

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

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public ClientType getClientType() {
        return clientType;
    }

    public void setClientType(ClientType clientType) {
        this.clientType = clientType;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Set<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(Set<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public String getCert() {
        return cert;
    }

    public void setCert(String cert) {
        this.cert = cert;
    }

    public String getCertSubjectDn() {
        return certSubjectDn;
    }

    public void setCertSubjectDn(String certSubjectDn) {
        this.certSubjectDn = certSubjectDn;
    }

    public Set<String> getManagers() {
        return managers;
    }

    public void setManagers(Set<String> managers) {
        this.managers = managers;
    }

    public Map<String, String> getLabels() {
        return labels;
    }

    public void setLabels(Map<String, String> labels) {
        this.labels = labels;
    }

    public Set<String> getAccessPolicies() {
        return accessPolicies;
    }

    public void setAccessPolicies(Set<String> accessPolicies) {
        this.accessPolicies = accessPolicies;
    }

    public boolean isDisable() {
        return disable;
    }

    public void setDisable(boolean disable) {
        this.disable = disable;
    }
}
