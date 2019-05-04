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


import io.vertx.core.json.JsonObject;

import java.util.Set;

public class AccessToken {

    private JsonObject sub;
    private Set<String> scopes;
    private String clientId;
    private long exp;

    public AccessToken() {
        //Default constructor
    }

    public AccessToken(JsonObject sub, Set<String> scopes, String clientId, long exp) {
        this.sub = sub;
        this.scopes = scopes;
        this.clientId = clientId;
        this.exp = exp;
    }

    public JsonObject getSub() {
        return sub;
    }

    public void setSub(JsonObject sub) {
        this.sub = sub;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public long getExp() {
        return exp;
    }

    public void setExp(long exp) {
        this.exp = exp;
    }
}
