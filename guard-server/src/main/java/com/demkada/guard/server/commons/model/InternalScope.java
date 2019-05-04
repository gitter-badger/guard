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


public enum InternalScope {
    GUARD_READ_CLIENTS,
    GUARD_CREATE_CLIENTS,
    GUARD_UPDATE_CLIENTS,
    GUARD_DELETE_CLIENTS,
    GUARD_READ_USERS,
    GUARD_CREATE_USERS,
    GUARD_UPDATE_USERS,
    GUARD_DELETE_USERS,
    GUARD_READ_SCOPES,
    GUARD_CREATE_SCOPES,
    GUARD_UPDATE_SCOPES,
    GUARD_CREATE_CONSENTS,
    GUARD_READ_CONSENTS,
    GUARD_DELETE_CONSENTS,
    GUARD_READ_AUDIT_TRAILS,
    GUARD_READ_AUTHENTICATION_HISTORY,
    GUARD_GENERATE_USER_TOKEN
}
