package com.demkada.guard.server.oauth2;

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


import com.demkada.guard.server.commons.model.*;
import com.demkada.guard.server.commons.utils.*;
import info.archinnov.achilles.generated.ManagerFactoryBuilder_For_Guard;
import info.archinnov.achilles.generated.manager.AuthZCode_Manager;
import io.vertx.core.AsyncResult;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static com.demkada.guard.server.commons.utils.Utils.getRedirectUri;

class AuthorizeService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizeService.class);

    private final Vertx vertx;

    private static final String SERVER_ERROR_MESSAGE = "server_error for request by client: ";

    private final AuthZCode_Manager authZCodeManager;

    AuthorizeService(Vertx vertx) {
        this.vertx = vertx;
        authZCodeManager = ManagerFactoryBuilder_For_Guard
                .builder(CassandraDriver.getOrCreate(vertx.getOrCreateContext().config()).getCluster())
                .withDefaultKeyspaceName(Constant.GUARD)
                .doForceSchemaCreation(false)
                .build()
                .forAuthZCode();
    }

    void handle(RoutingContext context) {
        Client client = context.get(Constant.CURRENT_CLIENT);
        String scope = context.request().getParam("scope");
        String nonce = context.request().getParam("nonce");
        String type = context.request().getParam("response_type");
        if (Utils.isStrEmpty(type) || !Utils.isEnumValid(ResponseType.class, type)) {
            handleError(context, Constant.OAUTH2_ERROR_CODE_UNSUPPORTED_RESPONSE_TYPE);
        }
        else if (Utils.isStrEmpty(scope)) {
            handleError(context, Constant.OAUTH2_ERROR_CODE_INVALID_SCOPE);
        }
        else {
            ResponseType responseType = ResponseType.valueOf(type);
            final List<String> scopeNames = Arrays.asList(scope.trim().split(" "));
            final List<Scope> scopes = new ArrayList<>();
            AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_SCOPES));
            AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.SCOPE_NAME, scopeNames));
            vertx.eventBus().send(Constant.SCOPE_MANAGER_QUEUE, entries.get(), options.get(), res -> {
                if (res.succeeded()) {
                    JsonObject body = (JsonObject) res.result().body();
                    JsonArray array = body.getJsonArray(Constant.RESPONSE);
                    if (array.isEmpty()) {
                        handleError(context, Constant.OAUTH2_ERROR_CODE_INVALID_SCOPE);
                    }
                    else {
                        setScopeList(context, client.getId(), scopes, array);
                        if (scopes.stream().anyMatch(match -> (Objects.isNull(match.getAuthorizedFlows()) || match.getAuthorizedFlows().isEmpty()) || (match.getAuthorizedFlows().contains(GrantType.authorization_code) || match.getAuthorizedFlows().contains(GrantType.implicit)))) {
                            handleAuthorize(context, client, context.get(Constant.CURRENT_REDIRECT_URI), responseType, scopeNames, scopes, nonce);
                        }
                        else {
                            handleError(context, Constant.OAUTH2_ERROR_CODE_INVALID_SCOPE);
                        }
                    }
                }
                else {
                    LOGGER.debug(SERVER_ERROR_MESSAGE + client.getId(), new GuardException(res.cause()));
                    handleError(context, Constant.OAUTH2_ERROR_CODE_SERVER_ERROR);
                }
            });
        }
    }

    private void handleError(RoutingContext context, String error) {
        String state = context.request().getParam(Constant.STATE);
        QueryString queryString = new QueryString(Constant.ERROR, error);
        if (!Utils.isStrEmpty(state)) {
            queryString.add("state", state);
        }
        final String uri = getRedirectUri(context.get(Constant.CURRENT_REDIRECT_URI), queryString.getQuery());
        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).putHeader(Constant.LOCATION, uri).setStatusCode(302).end();
    }

    private void setScopeList(RoutingContext context, String clientId, List<Scope> scopes, JsonArray array) {
        array.forEach(o -> {
            JsonObject object = (JsonObject) o;
            final Scope s = object.mapTo(Scope.class);
            scopes.add(s);
            if (s.isRestricted() && !s.getClientIdList().contains(clientId)) {
                handleError(context, Constant.OAUTH2_ERROR_CODE_UNAUTHORIZED_CLIENT);
            }
        });
    }

    private void handleAuthorize(RoutingContext context, Client client, String redirectUri, ResponseType responseType, List<String> scopeNames, List<Scope> scopes, String nonce) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_CONSENTS);
        JsonObject entries = new JsonObject()
                .put(Constant.SCOPE_NAME, scopeNames)
                .put(Constant.USER_EMAIL, context.user().principal().getString(Constant.EMAIL))
                .put(Constant.CLIENT_ID, client.getId());
        vertx.eventBus().send(Constant.CONSENT_MANAGER_QUEUE, entries, options, ar -> {
            if (ar.succeeded()) {
                handleAuthorizationRequest(context, responseType, scopes, scopeNames, client, redirectUri, nonce, ar);
            }
            else {
                LOGGER.debug(ar.cause().getMessage() + " " + client.getId(), new GuardException(ar.cause()));
                handleError(context, Constant.OAUTH2_ERROR_CODE_UNAUTHORIZED_CLIENT);
            }
        });
    }

    private void handleAuthorizationRequest(RoutingContext context, ResponseType responseType, List<Scope> scopes, List<String> scopeName, Client c, String redirectUri, String nonce, AsyncResult<Message<Object>> ar) {
        final Set<String> consents = new HashSet<>();
        JsonObject b = (JsonObject) ar.result().body();
        JsonArray array = b.getJsonArray(Constant.RESPONSE);
        array.forEach(o -> {
            JsonObject object = (JsonObject) o;
            consents.add(object.getString("scopeName"));
        });
        List<String> toBeConsented = new ArrayList<>();
        scopeName.forEach(s -> {
            if (!consents.contains(s)) {
                toBeConsented.add(s);
            }
            if (scopes.stream().anyMatch(scope -> s.equalsIgnoreCase(scope.getName()) && (Objects.nonNull(scope.getClientIdListForImplicitConsent()) && scope.getClientIdListForImplicitConsent().contains(c.getId())))) {
                toBeConsented.remove(s);
            }
        });
        if (toBeConsented.isEmpty()) {
            String state = context.request().getParam(Constant.STATE);
            AtomicReference<QueryString> queryString = new AtomicReference<>();
            if (Objects.nonNull(state)) {
                queryString.set(new QueryString("state", state));
            }
            if ((responseType.equals(ResponseType.token) || responseType.equals(ResponseType.id_token)) && (scopes.stream().noneMatch(Scope::isMachineMFA))) {
                handleImplicitRequest(context, scopeName, c, redirectUri, ar, state, responseType, nonce);
            }
            else if (responseType.equals(ResponseType.code)) {
                handleAuthZCodeRequest(context, c, redirectUri, ar, consents, queryString, scopes, state, nonce);
            }
            else {
                handleError(context, Constant.OAUTH2_ERROR_CODE_UNSUPPORTED_RESPONSE_TYPE);
            }
        }
        else {
            List<String> mfaRequired = scopes.stream()
                    .filter(s -> toBeConsented.contains(s.getName()) && s.isEndUserMFA())
                    .map(Scope::getName)
                    .collect(Collectors.toList());
            requestUserConsent(context, consents, toBeConsented, mfaRequired, c.getId(), c.getName(), redirectUri, scopes);
        }
    }

    private void handleImplicitRequest(RoutingContext context, List<String> scopeName, Client c, String redirectUri, AsyncResult<Message<Object>> ar, String state, ResponseType responseType, String nonce) {
        if (responseType.equals(ResponseType.id_token)) {
            if (scopeName.contains(Constant.OPENID) && Objects.nonNull(nonce) && !nonce.isEmpty()) {
                handleOAuthOidcImplicitFlow(context, scopeName, c, redirectUri, ar, state, responseType, nonce);
            }
            else {
                LOGGER.debug(SERVER_ERROR_MESSAGE + c.getId(), new GuardException(ar.cause()));
                handleError(context, Constant.OAUTH2_ERROR_CODE_INVALID_REQUEST);
            }
        }
        else {
            handleOAuthOidcImplicitFlow(context, scopeName, c, redirectUri, ar, state, responseType, null);
        }
    }

    private void handleOAuthOidcImplicitFlow(RoutingContext context, List<String> scopeName, Client c, String redirectUri, AsyncResult<Message<Object>> ar, String state, ResponseType responseType, String nonce) {
        Set<String> scopes = new HashSet<>();
        scopeName.forEach(s -> scopes.add(new JsonObject().put("name", s).encode()));
        AccessToken accessToken = new AccessToken(context.user().principal(), scopes, c.getId(), 60L);
        AtomicReference<DeliveryOptions> options = new AtomicReference<>();
        AtomicReference<JsonObject> entries = new AtomicReference<>();
        options.set(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GENERATE_OAUTH2_TOKEN));
        JsonObject object = new JsonObject().put(Constant.PAYLOAD, JsonObject.mapFrom(accessToken));
        if (Objects.nonNull(nonce)) {
            object.put(Constant.NONCE, nonce);
        }
        entries.set(object);
        this.vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), asyncResult -> {
            if (asyncResult.succeeded()) {
                JsonObject resp = ((JsonObject) asyncResult.result().body()).getJsonObject(Constant.RESPONSE);
                QueryString qs = new QueryString();
                if (responseType.equals(ResponseType.id_token)) {
                    qs.add(Constant.ID_TOKEN, resp.getString(Constant.ID_TOKEN));
                }
                else {
                    qs.add(Constant.ACCESS_TOKEN, resp.getString(Constant.ACCESS_TOKEN));
                    qs.add(Constant.TOKEN_TYPE, Constant.BEARER);
                }
                qs.add(Constant.EXPIRE_IN, String.valueOf(TimeUnit.SECONDS.convert(accessToken.getExp(), TimeUnit.MINUTES)));
                if (Objects.nonNull(state)) {
                    qs.add(Constant.STATE, state);
                }
                String uri = redirectUri + "#"  + qs.getQuery();
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                        .putHeader("Cache-Control", "no-store")
                        .putHeader("Pragma", "no-cache")
                        .putHeader(Constant.LOCATION, uri)
                        .setStatusCode(302).end();
            }
            else {
                LOGGER.debug(SERVER_ERROR_MESSAGE + c.getId(), new GuardException(ar.cause()));
                handleError(context, Constant.OAUTH2_ERROR_CODE_SERVER_ERROR);
            }
        });
    }


    private void handleAuthZCodeRequest(RoutingContext context, Client c, String redirectUri, AsyncResult<Message<Object>> ar, Set<String> consents, AtomicReference<QueryString> queryString, List<Scope> scopes, String state, String nonce) {
        AuthZCode authZCode = getAuthZCode(c, redirectUri, consents, scopes, state);
        if (Objects.nonNull(nonce) && !nonce.isEmpty()) {
            authZCode.setNonce(nonce);
        }
        JsonArray p = new JsonArray().add(context.user().principal().encode());
        AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_STRING_SET));
        AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, p));
        vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            if (reply.succeeded()) {
                JsonObject response = (JsonObject) reply.result().body();
                authZCode.setPrincipal(response.getJsonArray(Constant.RESPONSE).getString(0));
                vertx.executeBlocking(f -> {
                    authZCodeManager.crud().insert(authZCode).usingTimeToLive(300).execute();
                    f.complete();
                }, r -> {
                    if (r.succeeded()) {
                        QueryString qs = queryString.get();
                        if (Objects.nonNull(qs)) {
                            qs.add("code", authZCode.getCode());
                        }
                        else {
                            qs = new QueryString("code", authZCode.getCode());
                        }

                        String uri = getRedirectUri(redirectUri, qs.getQuery());
                        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).putHeader(Constant.LOCATION, uri).setStatusCode(302).end();
                    }
                    else {
                        LOGGER.debug(SERVER_ERROR_MESSAGE + c.getId(), new GuardException(ar.cause()));
                        handleError(context, Constant.OAUTH2_ERROR_CODE_SERVER_ERROR);
                    }
                });

            }
            else {
                LOGGER.debug(SERVER_ERROR_MESSAGE + c.getId(), new GuardException(ar.cause()));
                handleError(context, Constant.OAUTH2_ERROR_CODE_SERVER_ERROR);
            }
        });
    }

    private AuthZCode getAuthZCode(Client c, String redirectUri, Set<String> consents, List<Scope> scopes, String state) {
        AuthZCode authZCode = new AuthZCode();
        authZCode.setOneShotScopes(new HashSet<>());
        authZCode.setCode(UUID.randomUUID().toString());
        authZCode.setClientId(c.getId());
        authZCode.setClientName(c.getName());
        authZCode.setRedirectUri(redirectUri);
        authZCode.setRefreshTokenTTL(scopes.stream().map(Scope::getRefreshTokenTTL).mapToInt(s -> s).min().orElse((int) Constant.DEFAULT_REFRESH_TOKEN_TTL));
        if (Objects.nonNull(state) && !state.isEmpty()) {
            authZCode.setState(state);
        }
        Set<String> consentedScope = new HashSet<>();
        scopes.forEach(s -> {
            if (s.isOneShot()) {
                authZCode.getOneShotScopes().add(s.getName());
            }
            if (consents.contains(s.getName())) {
                consentedScope.add(new JsonObject().put("name", s.getName()).put("machineMFA", s.isMachineMFA()).put("caChain", s.getTrustCaChain()).encode());
            }
        });
        authZCode.setScopes(consentedScope);
        return authZCode;
    }

    private void requestUserConsent(RoutingContext context, Set<String> consentSet, List<String> toBeConsented, List<String> mfaRequired, String id, String name, String redirectUri, List<Scope> scopes) {
        QueryString queryString = new QueryString();
        consentSet.forEach(s -> queryString.add("consented", s));
        toBeConsented.forEach(s -> queryString.add("to_be_consented", s));
        if (!mfaRequired.isEmpty()) {
            mfaRequired.forEach(s -> queryString.add("mfa_required", s));
        }
        queryString.add(Constant.ORIGINAL_URL, context.request().absoluteURI());
        queryString.add(Constant.CLIENT_NAME, name);
        queryString.add(Constant.CLIENT_ID, id);
        queryString.add(Constant.REDIRECT_URI, redirectUri);
        if (Objects.nonNull(context.request().getParam(Constant.STATE))) {
            queryString.add(Constant.STATE, context.request().getParam(Constant.STATE));
        }
        if (scopes.stream().anyMatch(s -> Objects.nonNull(s.getConsentUrl()) && !s.getConsentUrl().isEmpty())) {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                    .putHeader(Constant.LOCATION, scopes.stream().filter(s -> Objects.nonNull(s.getConsentUrl()) && !s.getConsentUrl().isEmpty()).findFirst().get().getConsentUrl() + "?" + queryString.getQuery())
                    .setStatusCode(302).end();
        }
        else {
            context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                    .putHeader(Constant.LOCATION, vertx.getOrCreateContext().config().getString(Constant.GUARD_SERVER_HOST, "https://localhost:8443") + "/#/consent?" + queryString.getQuery())
                    .setStatusCode(302).end();
        }
    }

}
