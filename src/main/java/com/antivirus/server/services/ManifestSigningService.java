package com.antivirus.server.services;

import com.antivirus.server.dto.ManifestHeaderDto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.util.Base64;

@Service
public class ManifestSigningService {

    private final String magicNumber;
    private final String keyStorePath;
    private final String keyStorePassword;
    private final String keyStoreType;
    private final String keyAlias;

    public ManifestSigningService(
            @Value("${av.magic}") String magicNumber,
            @Value("${server.ssl.key-store}") String keyStorePath,
            @Value("${server.ssl.key-store-password}") String keyStorePassword,
            @Value("${server.ssl.key-store-type}") String keyStoreType,
            @Value("${server.ssl.key-alias}") String keyAlias
    ) {
        this.magicNumber = magicNumber;
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.keyStoreType = keyStoreType;
        this.keyAlias = keyAlias;
    }

    public String getMagicNumber() { return magicNumber; }


    public ManifestHeaderDto buildSignedHeader(OffsetDateTime releaseDate, long count) {
        try {
            String data = magicNumber + "|" + releaseDate.toEpochSecond() + "|" + count;
            String signatureB64 = signString(data);
            return new ManifestHeaderDto(magicNumber, releaseDate, count, signatureB64);
        } catch (Exception e) {
            throw new RuntimeException("Cannot build signed header", e);
        }
    }

    public X509Certificate getServerCertificate() {
        try {
            KeyStore ks = KeyStore.getInstance(keyStoreType);
            try (FileInputStream fis = new FileInputStream(keyStorePath)) {
                ks.load(fis, keyStorePassword.toCharArray());
            }
            return (X509Certificate) ks.getCertificate(keyAlias);
        } catch (Exception e) {
            throw new RuntimeException("Cannot load server certificate", e);
        }
    }

    public PrivateKey loadPrivateKeyForSigning() {
        try {
            KeyStore ks = KeyStore.getInstance(keyStoreType);
            try (FileInputStream fis = new FileInputStream(keyStorePath)) {
                ks.load(fis, keyStorePassword.toCharArray());
            }
            Key key = ks.getKey(keyAlias, keyStorePassword.toCharArray());
            if (key instanceof PrivateKey pk) return pk;
            throw new IllegalStateException("Private key not found for alias: " + keyAlias);
        } catch (Exception e) {
            throw new RuntimeException("Cannot load private key", e);
        }
    }


    public String signTextBase64(String text) {
        return signString(text);
    }


    public String signString(String text) {
        try {
            var pk = loadPrivateKeyForSigning();
            var sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(pk);
            sig.update(text.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(sig.sign());
        } catch (Exception e) {
            throw new RuntimeException("Cannot sign text", e);
        }
    }
}
