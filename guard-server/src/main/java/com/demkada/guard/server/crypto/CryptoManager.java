package com.demkada.guard.server.crypto;

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



import ch.ntb.inf.kmip.attributes.Name;
import ch.ntb.inf.kmip.attributes.UniqueIdentifier;
import ch.ntb.inf.kmip.container.KMIPBatch;
import ch.ntb.inf.kmip.container.KMIPContainer;
import ch.ntb.inf.kmip.kmipenum.EnumCredentialType;
import ch.ntb.inf.kmip.kmipenum.EnumOperation;
import ch.ntb.inf.kmip.kmipenum.EnumTag;
import ch.ntb.inf.kmip.objects.Authentication;
import ch.ntb.inf.kmip.objects.CredentialValue;
import ch.ntb.inf.kmip.objects.base.Attribute;
import ch.ntb.inf.kmip.objects.base.Credential;
import ch.ntb.inf.kmip.objects.base.KeyBlock;
import ch.ntb.inf.kmip.objects.managed.ManagedObject;
import ch.ntb.inf.kmip.objects.managed.SymmetricKey;
import ch.ntb.inf.kmip.process.decoder.*;
import ch.ntb.inf.kmip.process.encoder.KMIPEncoder;
import ch.ntb.inf.kmip.process.encoder.KMIPEncoderInterface;
import ch.ntb.inf.kmip.types.KMIPByteString;
import com.demkada.guard.server.commons.model.ErrorCodes;
import com.demkada.guard.server.commons.utils.Constant;
import com.demkada.guard.server.commons.utils.GuardException;
import com.demkada.guard.server.commons.utils.Utils;
import com.demkada.guard.server.commons.utils.kmip.GuardKMIPTransport;
import com.demkada.guard.server.commons.utils.kmip.GuardKMIPTransportSocket;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;


public class CryptoManager extends AbstractVerticle {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoManager.class);
    private static final String PKCS_12 = "PKCS12";

    private RSAPublicKey rsaPublicKey;
    private Jwe jwe;
    private Jwt jwt;
    private DataCipher dataCipher;

    @Override
    public void start(Future<Void> startFuture) {
        try {
            Key dataCipherKey;
            Key primaryKeyCipherKey;
            KeyPair keyPair;
            if (config().containsKey(Constant.GUARD_KMIP_SERVER) && config().getBoolean(Constant.GUARD_KMIP_SERVER)) {
                GuardKMIPTransport transportLayer = new GuardKMIPTransportSocket();
                transportLayer.setTargetHostname(config().getString(Constant.GUARD_KMIP_SERVER_HOST));
                transportLayer.setPort(config().getInteger(Constant.GUARD_KMIP_SERVER_PORT));
                transportLayer.setKeyStoreLocation(config().getString(Constant.GUARD_KMIP_SERVER_KEYSTORE_PATH));
                transportLayer.setKeyStorePW(config().getString(Constant.GUARD_KMIP_SERVER_KEYSTORE_PASS));
                transportLayer.setKeystoreCertificateAlias(config().getString(Constant.GUARD_KMIP_SERVER_KEYSTORE_CERT_ALIAS));

                String userName =config().getString(Constant.GUARD_KMIP_SERVER_USER_LOGIN);
                String password = (config().getString(Constant.GUARD_KMIP_SERVER_USER_PASS));

                keyPair = getKeyPairFromKMIPServer(userName, password, transportLayer);
                primaryKeyCipherKey = getSecretKeyFromKMIPServer(userName, password, transportLayer, config().getString(Constant.GUARD_KMIP_SERVER_AES_PK_CIPHER_KEY));
                dataCipherKey = getSecretKeyFromKMIPServer(userName, password, transportLayer, config().getString(Constant.GUARD_KMIP_SERVER_AES_DATA_CIPHER_KEY));
            } else {
                keyPair = getKeyPairFromFileSystem();
                primaryKeyCipherKey = getSecretKeyFromFileSystem(config().getString(Constant.GUARD_CRYPTO_AES_KEY_FOR_PK_ALIAS, "guard-aes-key-for-pk"));
                dataCipherKey = getSecretKeyFromFileSystem(config().getString(Constant.GUARD_CRYPTO_AES_KEY_FOR_DATA_ALIAS, "guard-aes-key-for-data"));
            }
            this.dataCipher = new DataCipher(vertx, primaryKeyCipherKey, dataCipherKey);
            if (Objects.nonNull(keyPair)) {
                this.rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            }
            this.jwt = new Jwt(vertx, keyPair);
            this.jwe = new Jwe(vertx, keyPair);
            vertx.eventBus().consumer(Constant.CRYPTO_MANAGER_QUEUE, this::onMessage);
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info(String.format("Guard Crypto manager %s is up and running", this.toString().split("@")[1]));
            }
            startFuture.complete();

        } catch (Exception e) {
            Exception exception = new GuardException(e);
            startFuture.fail(exception);
            LOGGER.error(exception.getMessage());
        }
    }

    private void onMessage(Message<JsonObject> message) {
        if (!message.headers().contains(Constant.ACTION)) {
            message.fail(ErrorCodes.NO_ACTION_SPECIFIED.ordinal(), "No action header specified");
        }

        String action = message.headers().get(Constant.ACTION);

        switch (action) {
            case Constant.ACTION_ENCRYPT_STRING:
                this.jwe.encryptString(message);
                break;

            case Constant.ACTION_DECRYPT_STRING:
                this.jwe.decryptString(message);
                break;

            case Constant.ACTION_GENERATE_USER_TOKEN:
                this.jwt.generateUserToken(message);
                break;

                case Constant.ACTION_GENERATE_OAUTH2_TOKEN:
                this.jwt.generateOAuth2Token(message);
                break;

            case Constant.ACTION_VALIDATE_TOKEN:
                this.jwt.validateToken(message);
                break;

            case Constant.ACTION_GENERATE_ENCRYPTED_USER_TOKEN:
                this.jwt.generateEncryptedUserToken(message);
                break;

            case Constant.ACTION_VALIDATE_ENCRYPTED_TOKEN:
                this.jwt.validateEncryptedToken(message);
                break;

            case Constant.ACTION_ENCRYPT_USER_MODEL_PII:
                this.dataCipher.encryptUserPii(message);
                break;

            case Constant.ACTION_DECRYPT_USER_MODEL_PII:
                this.dataCipher.decryptUserPii(message);
                break;

            case Constant.ACTION_ENCRYPT_PRIMARY_KEY:
                this.dataCipher.encryptPk(message);
                break;

            case Constant.ACTION_DECRYPT_PRIMARY_KEY:
                this.dataCipher.decryptPk(message);
                break;

            case Constant.ACTION_ENCRYPT_STRING_SET:
                this.dataCipher.encryptSet(message);
                break;

            case Constant.ACTION_DECRYPT_STRING_SET:
                this.dataCipher.decryptSet(message);
                break;

            case Constant.ACTION_GET_RSA_PUBLIC_KEY:
                this.getPublicKey(message);
                break;

            default:
                message.fail(ErrorCodes.BAD_ACTION.ordinal(), "Bad action: " + action);
        }
    }

    private void getPublicKey(Message<JsonObject> message) {
        if (Objects.nonNull(rsaPublicKey)) {
            message.reply(new JsonObject().put(Constant.RESPONSE, rsaPublicKey.getEncoded()));
        }
        else {
            message.fail(ErrorCodes.CRYPTO_ERROR.ordinal(), "RSA public key not found");
        }
    }

    private KeyPair getKeyPairFromFileSystem() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, GuardException {

        KeyStore joseKeyStore = KeyStore.getInstance(PKCS_12);
        char[] josePassword = config().getString(Constant.GUARD_CRYPTO_KEYSTORE_PASS_CONFIG_KEY, "D-Guard").toCharArray();
        InputStream joseInputStream;

        if (config().containsKey(Constant.GUARD_CRYPTO_KEYSTORE_CONFIG_KEY)) {
            joseInputStream = new FileInputStream(config().getString(Constant.GUARD_CRYPTO_KEYSTORE_CONFIG_KEY));
        }
        else {
            joseInputStream = vertx.getClass().getClassLoader().getResourceAsStream("guard-crypto-keystore.p12");
        }

        joseKeyStore.load(joseInputStream, josePassword);
        String joseAlias = config().getString(Constant.GUARD_CRYPTO_RSA_KEYPAIR_ALIAS, "guard-rsa-keypair");
        Key joseKey = joseKeyStore.getKey(joseAlias, josePassword);

        if (joseKey instanceof PrivateKey) {
            java.security.cert.Certificate cert = joseKeyStore.getCertificate(joseAlias);
            PublicKey publicKey = cert.getPublicKey();
            return new KeyPair(publicKey, (PrivateKey) joseKey);
        }
        else {
            throw new GuardException("Unable to load Jose Keypair");
        }
    }

    private Key getSecretKeyFromFileSystem(String alias) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore cryptoKeystore = KeyStore.getInstance(PKCS_12);
        char[] dataEncryptionPassword = config().getString(Constant.GUARD_CRYPTO_KEYSTORE_PASS_CONFIG_KEY, "D-Guard").toCharArray();
        InputStream cryptoKeystoreInputStream;

        if (config().containsKey(Constant.GUARD_CRYPTO_KEYSTORE_CONFIG_KEY)) {
            cryptoKeystoreInputStream = new FileInputStream(config().getString(Constant.GUARD_CRYPTO_KEYSTORE_CONFIG_KEY));
        }
        else {
            cryptoKeystoreInputStream = vertx.getClass().getClassLoader().getResourceAsStream("guard-crypto-keystore.p12");
        }

        cryptoKeystore.load(cryptoKeystoreInputStream, dataEncryptionPassword);

        return cryptoKeystore.getKey(alias, dataEncryptionPassword);
    }

    private KeyPair getKeyPairFromKMIPServer(String userName, String password, GuardKMIPTransport transportLayer) throws KMIPPaddingExpectedException, KMIPProtocolVersionException, KMIPUnexpectedAttributeNameException, KMIPUnexpectedTypeException, IOException, KMIPUnexpectedTagException, NoSuchAlgorithmException, InvalidKeySpecException, GuardException {
        List<Byte> keyInfoRequest = getKeyInfo(userName, password, transportLayer, config().getString(Constant.GUARD_KMIP_SERVER_RSA_PRIVATE_KEY));
        KMIPByteString kmipByteString;
        KeyPair pair = null;
        KMIPDecoderInterface decoder = new KMIPDecoder();
        KMIPContainer keyInfoResponse = decoder.decodeResponse((ArrayList<Byte>) keyInfoRequest);
        if (Objects.nonNull(keyInfoResponse) && keyInfoResponse.getBatchCount() > 0) {
            String id = keyInfoResponse.getBatch(0).getAttributes().get(0).getValues()[0].getValueString();
            List<Byte> keyRequest = getKey(userName, password, id, transportLayer);
            KMIPContainer keyResponse = decoder.decodeResponse((ArrayList<Byte>) keyRequest);
            if (Objects.nonNull(keyResponse) && keyResponse.getBatchCount() > 0) {
                ManagedObject managedObject = keyResponse.getBatch(0).getManagedObject();
                if (managedObject.getTag().getValue() == EnumTag.PrivateKey) {
                    KeyBlock keyBlock = ((ch.ntb.inf.kmip.objects.managed.PrivateKey) managedObject).getKeyBlock();
                    kmipByteString = keyBlock.getKeyValue().getKeyMaterial().getKeyMaterialByteString();
                    RSAPrivateKeySpec keySpec = Utils.getRSAKeySpec(kmipByteString.getValue());
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
                    RSAPrivateCrtKey p = (RSAPrivateCrtKey) privateKey;
                    PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(p.getModulus(), p.getPublicExponent()));
                    pair = new KeyPair(publicKey, privateKey);
                }
                else {
                    throw new GuardException("Unable to load RSA keypair from KMIP Server");
                }
            }
            else {
                throw new GuardException("Unable to load RSA keypair from KMIP Server");
            }
        }
        return pair;
    }

    private Key getSecretKeyFromKMIPServer(String userName, String password, GuardKMIPTransport transportLayer, String keyName) throws KMIPPaddingExpectedException, KMIPProtocolVersionException, KMIPUnexpectedAttributeNameException, KMIPUnexpectedTypeException, IOException, KMIPUnexpectedTagException, GuardException {
        List<Byte> keyInfoRequest = getKeyInfo(userName, password, transportLayer, keyName);
        KMIPByteString kmipByteString;
        SecretKey secretKey = null;
        KMIPDecoderInterface decoder = new KMIPDecoder();
        KMIPContainer keyInfoResponse = decoder.decodeResponse((ArrayList<Byte>) keyInfoRequest);
        if (Objects.nonNull(keyInfoResponse) && keyInfoResponse.getBatchCount() > 0) {
            String id = keyInfoResponse.getBatch(0).getAttributes().get(0).getValues()[0].getValueString();
            List<Byte> keyRequest = getKey(userName, password, id, transportLayer);
            KMIPContainer keyResponse = decoder.decodeResponse((ArrayList<Byte>) keyRequest);
            if (Objects.nonNull(keyResponse) && keyResponse.getBatchCount() > 0) {
                ManagedObject managedObject = keyResponse.getBatch(0).getManagedObject();
                if (managedObject.getTag().getValue() == EnumTag.SymmetricKey) {
                    KeyBlock keyBlock = ((SymmetricKey) managedObject).getKeyBlock();
                    kmipByteString = keyBlock.getKeyValue().getKeyMaterial().getKeyMaterialByteString();
                    secretKey =  new SecretKeySpec(kmipByteString.getValue(), 0, kmipByteString.getValue().length, "AES");
                }
                else {
                    throw new GuardException("Unable to load AES key from KMIP Server");
                }
            }
            else {
                throw new GuardException("Unable to load AES key from KMIP Server");
            }
        }
        return secretKey;
    }

    private static List<Byte> getKeyInfo(String userName, String password, GuardKMIPTransport transportLayer, String keyName) {
        KMIPContainer container = new KMIPContainer();

        CredentialValue credentialValue = new CredentialValue(userName, password);
        Credential credential = new Credential();
        credential.setCredentialType(new EnumCredentialType(EnumCredentialType.UsernameAndPassword));
        credential.setCredentialValue(credentialValue);
        Authentication authentication = new Authentication(credential);
        container.setAuthentication(authentication);
        KMIPBatch batch = new KMIPBatch();
        batch.setOperation(EnumOperation.Locate);
        Attribute name = new Name();
        name.setValue(keyName, null);
        batch.addAttribute(name);
        container.addBatch(batch);
        container.calculateBatchCount();

        KMIPEncoderInterface encoder = new KMIPEncoder();
        ArrayList<Byte> ttlv = encoder.encodeRequest(container);
        return transportLayer.send(ttlv);
    }

    private static List<Byte> getKey(String userName, String password, String id, GuardKMIPTransport transportLayer) {
        KMIPContainer container = new KMIPContainer();

        CredentialValue credentialValue = new CredentialValue(userName, password);
        Credential credential = new Credential();
        credential.setCredentialType(new EnumCredentialType(EnumCredentialType.UsernameAndPassword));
        credential.setCredentialValue(credentialValue);
        Authentication authentication = new Authentication(credential);
        container.setAuthentication(authentication);
        KMIPBatch batch = new KMIPBatch();
        batch.setOperation(EnumOperation.Get);
        UniqueIdentifier uuid = new UniqueIdentifier();
        uuid.setValue(id, "Unique identifier");
        batch.addAttribute(uuid);
        container.addBatch(batch);
        container.calculateBatchCount();

        KMIPEncoderInterface encoder = new KMIPEncoder();
        ArrayList<Byte> ttlv = encoder.encodeRequest(container);
        return transportLayer.send(ttlv);
    }
}
