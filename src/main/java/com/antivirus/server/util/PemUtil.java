package com.antivirus.server.util;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class PemUtil {
    public static String toPem(X509Certificate cert) {
        try {
            String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}
