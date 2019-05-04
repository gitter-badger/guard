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
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;

import java.util.Objects;

public class GuardPrincipal extends AbstractUser {

    private JsonObject principal;

    public GuardPrincipal(JsonObject principal, PrincipalType type) {
        this.principal = principal;
        this.principal.remove("disable");

        this.principal.put(Constant.GUARD_SUB_TYPE, type.name());

        if (PrincipalType.APP.equals(PrincipalType.valueOf(this.principal.getString(Constant.GUARD_SUB_TYPE)))) {
            this.principal.remove("managers");
            this.principal.remove("redirectUris");

            this.principal.put(Constant.CLIENT_ID, this.principal.getString("id"));
            this.principal.remove("id");
            this.principal.put(Constant.CLIENT_NAME, this.principal.getString("name"));
            this.principal.remove("name");
        }
    }

    public void addClaim(String key, Object value) {
        this.principal.put(key, value);
    }

    @Override
    protected void doIsPermitted(String s, Handler<AsyncResult<Boolean>> handler) {
        Future<Boolean> future = Future.future();
        if (principal.containsKey(Constant.SCOPE) && Objects.nonNull(principal.getJsonArray(Constant.SCOPE)) && principal.getJsonArray(Constant.SCOPE).contains(s)) {
            future.complete(true);
        }
        else {
            future.fail("not authorized");
        }
        future.setHandler(handler);
    }

    @Override
    public JsonObject principal() {
        return this.principal;
    }

    @Override
    public void setAuthProvider(AuthProvider authProvider) {

    }
}
