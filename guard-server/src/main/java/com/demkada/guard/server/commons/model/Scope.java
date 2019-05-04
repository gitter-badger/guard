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

import java.util.HashSet;
import java.util.Set;

@Table(table= Constant.SCOPES_BY_NAME)
@Consistency(
        read = ConsistencyLevel.LOCAL_QUORUM,
        write = ConsistencyLevel.LOCAL_QUORUM,
        serial = ConsistencyLevel.LOCAL_SERIAL)
public class Scope {

    @Column(Constant.NAME)
    @PartitionKey
    private String name;

    @Column(Constant.EN_DESCRIPTION)
    private String enDescription;

    @Column(Constant.FR_DESCRIPTION)
    private String frDescription;

    @Column(Constant.RESTRICTED)
    private boolean restricted;

    @Column(Constant.CLIENT_ID_LIST)
    private Set<String> clientIdList = new HashSet<>();

    @Column(Constant.ONE_SHOT)
    private boolean oneShot;

    @Column(Constant.AUTHORIZED_FLOWS)
    private Set<@Enumerated(Enumerated.Encoding.NAME) GrantType> authorizedFlows = new HashSet<>();

    @Column(Constant.CLIENT_ID_LIST_FOR_IMPLICIT_CONSENT)
    private Set<String> clientIdListForImplicitConsent = new HashSet<>();

    @Column(Constant.SCOPE_MANAGERS)
    private Set<String> managers = new HashSet<>();

    @Column(Constant.CONSENT_URL)
    private String consentUrl;

    @Column(Constant.CONSENT_TTL)
    private int consentTTL;

    @Column(Constant.REFRESH_TOKEN_TTL)
    private int refreshTokenTTL;

    @Column(Constant.END_USER_MFA)
    private boolean endUserMFA;

    @Column(Constant.MACHINE_MFA)
    private boolean machineMFA;

    @Column(Constant.TRUST_CA_CHAIN)
    private String trustCaChain;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEnDescription() {
        return enDescription;
    }

    public void setEnDescription(String enDescription) {
        this.enDescription = enDescription;
    }

    public String getFrDescription() {
        return frDescription;
    }

    public void setFrDescription(String frDescription) {
        this.frDescription = frDescription;
    }

    public boolean isRestricted() {
        return restricted;
    }

    public void setRestricted(boolean restricted) {
        this.restricted = restricted;
    }

    public boolean isOneShot() {
        return oneShot;
    }

    public void setOneShot(boolean oneShot) {
        this.oneShot = oneShot;
    }

    public boolean isEndUserMFA() {
        return endUserMFA;
    }

    public void setEndUserMFA(boolean endUserMFA) {
        this.endUserMFA = endUserMFA;
    }

    public boolean isMachineMFA() {
        return machineMFA;
    }

    public void setMachineMFA(boolean machineMFA) {
        this.machineMFA = machineMFA;
    }

    public Set<String> getClientIdList() {
        return clientIdList;
    }

    public void setClientIdList(Set<String> clientIdList) {
        this.clientIdList = clientIdList;
    }

    public Set<String> getManagers() {
        return managers;
    }

    public void setManagers(Set<String> managers) {
        this.managers = managers;
    }

    public int getRefreshTokenTTL() {
        return refreshTokenTTL;
    }

    public void setRefreshTokenTTL(int refreshTokenTTL) {
        this.refreshTokenTTL = refreshTokenTTL;
    }

    public int getConsentTTL() {
        return consentTTL;
    }

    public void setConsentTTL(int consentTTL) {
        this.consentTTL = consentTTL;
    }

    public String getTrustCaChain() {
        return trustCaChain;
    }

    public void setTrustCaChain(String trustCaChain) {
        this.trustCaChain = trustCaChain;
    }

    public String getConsentUrl() {
        return consentUrl;
    }

    public void setConsentUrl(String consentUrl) {
        this.consentUrl = consentUrl;
    }

    public Set<String> getClientIdListForImplicitConsent() {
        return clientIdListForImplicitConsent;
    }

    public void setClientIdListForImplicitConsent(Set<String> clientIdListForImplicitConsent) {
        this.clientIdListForImplicitConsent = clientIdListForImplicitConsent;
    }

    public Set<GrantType> getAuthorizedFlows() {
        return authorizedFlows;
    }

    public void setAuthorizedFlows(Set<GrantType> authorizedFlows) {
        this.authorizedFlows = authorizedFlows;
    }
}
