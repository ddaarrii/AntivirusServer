package com.antivirus.server.services;

import com.antivirus.server.models.Signature;
import com.antivirus.server.repository.SignatureRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.security.PublicKey;

@Service
public class SignatureVerifier {

    private final SignatureRepository repo;
    private final ManifestSigningService manifestSigningService;
    private final SignatureService signatureService;

    public SignatureVerifier(SignatureRepository repo,
                             ManifestSigningService manifestSigningService,
                             SignatureService signatureService) {
        this.repo = repo;
        this.manifestSigningService = manifestSigningService;
        this.signatureService = signatureService;
    }

    /** каждые 5 минут */
    @Scheduled(cron = "0 */5 * * * *")
    public void verifyAll() {
        var cert = manifestSigningService.getServerCertificate();
        PublicKey publicKey = cert.getPublicKey();

        for (Signature s : repo.findAll()) {
            try {
                var recordBytes = SignatureBytes.buildRecordBytes(s);
                var signature   = s.getAvRecordSignature();
                if (signature == null || signature.length == 0) continue;

                var verifier = java.security.Signature.getInstance("SHA256withRSA");
                verifier.initVerify(publicKey);
                verifier.update(recordBytes);
                boolean ok = verifier.verify(signature);

                signatureService.saveVerifyResult(s.getId(), ok);
            } catch (Exception e) {
                signatureService.saveVerifyResult(s.getId(), false);
            }
        }
    }
}
