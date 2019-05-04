package com.demkada.guard.server.commons.utils;

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
import com.demkada.guard.server.commons.utils.kmip.Asn1Object;
import com.demkada.guard.server.commons.utils.kmip.DerParser;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.DeliveryOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.RoutingContext;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public final class Utils {

    private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

    private Utils() {
        //Hide public one
    }

    public static byte[] convertToByteArray(InputStream input) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[1024];
        while ((nRead = input.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        buffer.flush();
        return buffer.toByteArray();
    }

    public static void handleServerError(RoutingContext context, Logger logger, Throwable throwable) {
        String uuid = UUID.randomUUID().toString();
        logger.error(uuid, throwable);
        context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON).setStatusCode(500).end(new JsonObject().put(Constant.ERROR_CODE, uuid).put(Constant.HTTP_STATUS_CODE, 500).put(Constant.ERROR_MESSAGE, throwable.getMessage()).encode());
    }

    public static User sanitizeUser(User user) {
        user.setPwd(null);
        user.setSecurityQuestion(new HashMap<>());
        return user;
    }

    public static String stringToSha256ToBase32(String string) {
        return new Base32().encodeAsString(DigestUtils.sha256(string));
    }

    public static boolean isAdmin(JsonArray admins, String currentUser) {
        return Objects.nonNull(admins) && Objects.nonNull(currentUser) && admins.contains(currentUser);
    }

    public static void encryptManagers(Vertx vertx, Set<String> plainSet, Handler<AsyncResult<Set<String>>> handler) {
        Future<Set<String>> future = Future.future();
        if (Objects.nonNull(plainSet)) {
            List<String> managers = new ArrayList<>(plainSet);
            AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_STRING_SET));
            AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, new JsonArray(managers)));
            sendCryptoEventForSet(vertx, future, options, entries);
        }
        else {
            future.complete(Collections.emptySet());
        }
        future.setHandler(handler);
    }

    public static void decryptManagers(Vertx vertx, Set<String> ciphered, Handler<AsyncResult<Set<String>>> handler) {
        Future<Set<String>> future = Future.future();
        if (Objects.nonNull(ciphered)) {
            List<String> managers = new ArrayList<>(ciphered);
            AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_STRING_SET));
            AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, new JsonArray(managers)));
            sendCryptoEventForSet(vertx, future, options, entries);
        }
        else {
            future.complete(Collections.emptySet());
        }
        future.setHandler(handler);
    }

    public static void encryptpk(Vertx vertx, String plainSet, Handler<AsyncResult<String>> handler) {
        Future<String> future = Future.future();
        if (Objects.nonNull(plainSet)) {
            AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_ENCRYPT_PRIMARY_KEY));
            AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, plainSet));
            sendCryptoEventForPk(vertx, future, options, entries);
        }
        else {
            future.fail("null Primary key not allowed");
        }
        future.setHandler(handler);
    }


    public static void decryptPk(Vertx vertx, String ciphered, Handler<AsyncResult<String>> handler) {
        Future<String> future = Future.future();
        if (Objects.nonNull(ciphered)) {
            AtomicReference<DeliveryOptions> options = new AtomicReference<>(new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_DECRYPT_PRIMARY_KEY));
            AtomicReference<JsonObject> entries = new AtomicReference<>(new JsonObject().put(Constant.PAYLOAD, ciphered));
            sendCryptoEventForPk(vertx, future, options, entries);
        }
        else {
            future.fail("null Primary key not allowed");
        }
        future.setHandler(handler);
    }

    private static void sendCryptoEventForPk(Vertx vertx, Future<String> future, AtomicReference<DeliveryOptions> options, AtomicReference<JsonObject> entries) {
        vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            if (reply.succeeded()) {
                JsonObject response = (JsonObject) reply.result().body();
                future.complete(response.getString(Constant.RESPONSE));
            }
            else {
                future.fail(reply.cause());
            }
        });
    }

    private static void sendCryptoEventForSet(Vertx vertx, Future<Set<String>> future, AtomicReference<DeliveryOptions> options, AtomicReference<JsonObject> entries) {
        vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries.get(), options.get(), reply -> {
            if (reply.succeeded()) {
                final Set<String> mgr = new HashSet<>();
                JsonObject response = (JsonObject) reply.result().body();
                response.getJsonArray(Constant.RESPONSE).forEach(s -> mgr.add((String) s));
                future.complete(mgr);
            }
            else {
                future.fail(reply.cause());
            }
        });
    }

    public static RSAPrivateCrtKeySpec getRSAKeySpec(byte[] keyBytes) throws IOException  {

        DerParser parser = new DerParser(keyBytes);

        Asn1Object sequence = parser.read();
        if (sequence.getType() != DerParser.SEQUENCE)
            throw new IOException("Invalid DER: not a sequence");

        parser = sequence.getParser();

        parser.read();
        BigInteger modulus = parser.read().getInteger();
        BigInteger publicExp = parser.read().getInteger();
        BigInteger privateExp = parser.read().getInteger();
        BigInteger prime1 = parser.read().getInteger();
        BigInteger prime2 = parser.read().getInteger();
        BigInteger exp1 = parser.read().getInteger();
        BigInteger exp2 = parser.read().getInteger();
        BigInteger crtCoef = parser.read().getInteger();

        return new RSAPrivateCrtKeySpec(
                modulus, publicExp, privateExp, prime1, prime2,
                exp1, exp2, crtCoef);
    }

    public static void validateUserToken(Vertx vertx, RoutingContext context, DeliveryOptions options, JsonObject entries) {
        vertx.eventBus().send(Constant.CRYPTO_MANAGER_QUEUE, entries, options, reply -> {
            if (reply.succeeded()) {
                JsonObject resp = (JsonObject) reply.result().body();
                GuardPrincipal principal = new GuardPrincipal(resp.getJsonObject(Constant.RESPONSE), PrincipalType.END_USER);
                context.setUser(principal);
                context.next();
            }
            else {
                Utils.redirectToLoginPage(vertx, context);
            }
        });
    }

    public static User getUserFromPrincipal(JsonObject response) {
        User user = new User();
        user.setSub(response.getJsonObject(Constant.RESPONSE).getString(Constant.SUB));
        user.setEmail(response.getJsonObject(Constant.RESPONSE).getString(Constant.EMAIL));
        user.setEmailVerified(response.getJsonObject(Constant.RESPONSE).getBoolean(Constant.EMAIL_VERIFIED));
        user.setAddress(response.getJsonObject(Constant.RESPONSE).getString(Constant.ADDRESS));
        user.setPhoneNumber(response.getJsonObject(Constant.RESPONSE).getString(Constant.PHONE_NUMBER));
        user.setPhoneNumberVerified(response.getJsonObject(Constant.RESPONSE).getBoolean(Constant.PHONE_NUMBER_VERIFIED));
        user.setGivenName(response.getJsonObject(Constant.RESPONSE).getString(Constant.GIVEN_NAME));
        user.setIdOrigin(response.getJsonObject(Constant.RESPONSE).getString(Constant.ID_ORIGIN));
        return user;
    }

    /**
     * Check if a String enum value is not null and exist
     */
    public static <E extends Enum<E>> boolean isEnumValid(Class<E> enumClass, String name){
        if (name == null || name.isEmpty()) {
            return false;
        }

        try {
            Enum.valueOf(enumClass, name);
        }
        catch (IllegalArgumentException e) {
            return  false;
        }

        return  true;
    }

    public static boolean isStrEmpty(String value){
        return value == null || value.isEmpty();
    }

    static boolean isStrNotEmpty(String value){
        return !isStrEmpty(value);
    }

    public static JsonObject convertUrlFormEncodedToJsonObject(String input) {
        JsonObject body = new JsonObject();
        Arrays.asList(input.split("&")).forEach(q -> {
            try {
                String[] query = q.split("=");
                if (2 == query.length) {
                    body.put(URLDecoder.decode(query[0], "UTF-8"), URLDecoder.decode(query[1], "UTF-8"));
                }
            } catch (UnsupportedEncodingException e) {
                //Nothing to parse
            }
        });
        return body;
    }

    public static void redirectToLoginPage(Vertx vertx, RoutingContext context) {
        DeliveryOptions options = new DeliveryOptions().addHeader(Constant.ACTION, Constant.ACTION_GET_ADAPTERS);
        JsonObject entries = new JsonObject();
        vertx.eventBus().send(Constant.ADAPTER_MANAGER_QUEUE, entries, options, res -> {
            if (res.succeeded()) {
                AtomicReference<Adapter> adapter = new AtomicReference<>();
                ((JsonObject) res.result().body()).getJsonArray(Constant.RESPONSE)
                        .stream().forEach(o -> {
                    if ((context.request().host().split(":")[0].equalsIgnoreCase(((JsonObject) o).getString("triggerOnHostname"))) || (((JsonObject) o).getString("id")).equalsIgnoreCase(context.get(Constant.ADAPTER_ID))) {
                        adapter.set(((JsonObject) o).mapTo(Adapter.class));
                    }
                });
                if (Objects.nonNull(adapter.get())) {
                    Utils.redirectToAdapter(vertx, context, adapter.get());
                }
                else {
                    context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                            .putHeader(Constant.LOCATION, vertx.getOrCreateContext().config().getString(Constant.GUARD_SERVER_HOST, "https://localhost:8443") + "/#/auth/sign-in?" + new QueryString(Constant.ORIGINAL_URL, context.request().absoluteURI()).getQuery())
                            .setStatusCode(302).end();
                }
            }
            else {
                context.response().putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON)
                        .putHeader(Constant.LOCATION, vertx.getOrCreateContext().config().getString(Constant.GUARD_SERVER_HOST, "https://localhost:8443") + "/#/auth/sign-in?" + new QueryString(Constant.ORIGINAL_URL, context.request().absoluteURI()).getQuery())
                        .setStatusCode(302).end();
            }
        });
    }

    private static boolean isSelfSigned(X509Certificate cert) {
        try {
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException | InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException sigEx) {
            return false;
        }
    }

    public static boolean validateCaChain(X509Certificate currentCert, X509Certificate clientCert, JsonObject client, X509Certificate... trustedCerts) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertificateException {
        boolean found = false;
        int i = trustedCerts.length;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        TrustAnchor anchor;
        Set<TrustAnchor> anchors;
        CertPath path;
        List<? extends Certificate> list;
        PKIXParameters params;
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");

        while (!found && i > 0) {
            anchor = new TrustAnchor(trustedCerts[--i], null);
            anchors = Collections.singleton(anchor);

            list = Collections.singletonList(currentCert);
            path = cf.generateCertPath(list);

            params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);

            if (currentCert.getIssuerDN().equals(trustedCerts[i].getSubjectDN())) {
                try {
                    validator.validate(path, params);
                    if (isSelfSigned(trustedCerts[i])) {
                        found = true;
                    } else if (!currentCert.equals(trustedCerts[i])) {
                        found = validateCaChain(trustedCerts[i], clientCert, client, trustedCerts);
                    }
                } catch (CertPathValidatorException e) {
                    found = false;
                }
            }
        }
        if (found) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            found = (Objects.nonNull(client.getString("certSubjectDn")) && clientCert.getSubjectDN().toString().equalsIgnoreCase(new X500Principal(client.getString("certSubjectDn")).toString())) ||
                    (Objects.nonNull(client.getString("cert")) && clientCert.equals(certificateFactory.generateCertificate(new ByteArrayInputStream(client.getString("cert").getBytes()))));
        }
        return found;
    }


    private static void redirectToAdapter(Vertx vertx, RoutingContext context, Adapter adapter) {
        HttpServerResponse response = context.response()
                .putHeader(Constant.CONTENT_TYPE, Constant.CONTENT_TYPE_JSON);
        String redirectUrl = "";
        String url = adapter.getAdapterUrl();
        String originalUrl = context.request().absoluteURI();
        if (Objects.nonNull(context.get(Constant.ORIGINAL_URL))) {
            originalUrl = context.get(Constant.ORIGINAL_URL);
        }
        if (adapter.getType().equals(AdapterType.NATIVE)) {
            redirectUrl = url + "?" + new QueryString(Constant.ORIGINAL_URL, originalUrl).getQuery();
        }
        else if (adapter.getType().equals(AdapterType.OIDC)){
            String state = UUID.randomUUID().toString();
            String nonce = Base64.getEncoder().encodeToString(new JsonObject().put(Constant.ORIGINAL_URL, originalUrl).put(Constant.STATE, state).put("redirect_uri", (String) context.get(Constant.CURRENT_REDIRECT_URI)).toBuffer().getBytes());
            Cookie cookie = Cookie.cookie(Constant.GUARD_ADAPTER_NONCE, nonce);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setSecure(true);
            if (vertx.getOrCreateContext().config().containsKey(Constant.GUARD_COOKIE_DOMAIN)) {
                cookie.setDomain(vertx.getOrCreateContext().config().getString(Constant.GUARD_COOKIE_DOMAIN));
            }
            context.addCookie(cookie);
            QueryString queryString = new QueryString("response_type", "id_token");
            queryString.add(Constant.CLIENT_ID, adapter.getClientId());
            queryString.add(Constant.REDIRECT_URI, vertx.getOrCreateContext().config().getString(Constant.GUARD_SERVER_HOST, "https://localhost:8443") + "/oidc-adapter?id=" + adapter.getId());
            queryString.add(Constant.SCOPE, "openid");
            queryString.add(Constant.STATE, state);
            queryString.add(Constant.NONCE, nonce);
            redirectUrl = url + "?" + queryString.getQuery();
        }
        if (Objects.nonNull(context.request().query())) {
            StringBuilder originalQueryBuilder = new StringBuilder();
            Arrays.asList(context.request().query().split("&")).forEach(qs -> {
                if (!Constant.ADAPTER_ID.equalsIgnoreCase(qs.split("=")[0]) && !Constant.ORIGINAL_URL.equalsIgnoreCase(qs.split("=")[0]) && !Constant.STATE.equalsIgnoreCase(qs.split("=")[0]) && !Constant.REDIRECT_URI.equalsIgnoreCase(qs.split("=")[0])) {
                    originalQueryBuilder.append("guard_original_").append(qs.split("=")[0]).append("=").append(qs.split("=")[1]).append("&");
                }
            });
            if (!originalQueryBuilder.toString().isEmpty()) {
                redirectUrl = redirectUrl + "&" + originalQueryBuilder.toString().replaceAll("&$", "");
            }
        }
        if (Objects.nonNull(context.get(Constant.ADAPTER_ID)) && Objects.nonNull(context.get(Constant.ORIGINAL_URL))) {
            response.setStatusCode(200).end(new JsonObject().put("url", redirectUrl).encode());
        }
        else {
            response.setStatusCode(302).putHeader(Constant.LOCATION, redirectUrl).end();
        }
    }

    public static String getRedirectUri(String redirectUri, String queryString) {
        String uri = redirectUri;
        if (redirectUri.split("\\?").length != 1) {
            uri = uri + "&" + queryString;
        }
        else {
            uri = uri + "?" + queryString;
        }
        return uri;
    }
}

