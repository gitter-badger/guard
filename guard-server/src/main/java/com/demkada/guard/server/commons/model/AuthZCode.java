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

import java.util.Set;

@Table(table= Constant.AUTHZ_CODE)
@Consistency(
         read = ConsistencyLevel.LOCAL_QUORUM,
        write = ConsistencyLevel.LOCAL_QUORUM,
        serial = ConsistencyLevel.LOCAL_SERIAL)
public class AuthZCode {

    @Column(Constant.CODE)
    @PartitionKey
    private String code;

    @Column(Constant.CLIENT_ID)
    @ClusteringColumn
    private String clientId;

    @Column(Constant.REDIRECT_URI)
    private String redirectUri;

    @Column(Constant.STATE)
    private String state;

    @Column(Constant.NONCE)
    private String nonce;

    @Column(Constant.REFRESH_TOKEN_TTL)
    private int refreshTokenTTL;

    @Column(Constant.SCOPE)
    private Set<String> scopes;

    @Column(Constant.ONE_SHOT_SCOPES)
    private Set<String> oneShotScopes;

    @Column(Constant.PRINCIPAL)
    private String principal;

    @Column(Constant.CLIENT_NAME)
    private String clientName;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public int getRefreshTokenTTL() {
        return refreshTokenTTL;
    }

    public void setRefreshTokenTTL(int refreshTokenTTL) {
        this.refreshTokenTTL = refreshTokenTTL;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public Set<String> getOneShotScopes() {
        return oneShotScopes;
    }

    public void setOneShotScopes(Set<String> oneShotScopes) {
        this.oneShotScopes = oneShotScopes;
    }
}
