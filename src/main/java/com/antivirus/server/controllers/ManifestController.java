package com.antivirus.server.controllers;

import com.antivirus.server.dto.ManifestDto;
import com.antivirus.server.dto.ManifestHeaderDto;
import com.antivirus.server.models.Signature;
import com.antivirus.server.services.ManifestSigningService;
import com.antivirus.server.services.SignatureBytes;
import com.antivirus.server.services.SignatureService;
import com.antivirus.server.util.PemUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

@RestController
public class ManifestController {

    private final SignatureService service;
    private final ManifestSigningService signing;

    public ManifestController(SignatureService service, ManifestSigningService signing) {
        this.service = service;
        this.signing = signing;
    }


    @GetMapping("/manifest")
    public ManifestDto getManifest() {
        List<Signature> records = service.getAllSignatures();
        OffsetDateTime date = service.getReleaseDate();
        ManifestHeaderDto header = signing.buildSignedHeader(date, records.size());
        return new ManifestDto(header, records);
    }


    @GetMapping(value = "/manifest/cert", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> getCertificatePem() {
        X509Certificate cert = signing.getServerCertificate();
        return ResponseEntity.ok(PemUtil.toPem(cert));
    }


    @GetMapping(value = "/api/signatures/bundle", produces = "multipart/mixed")
    @Transactional(readOnly = true)
    public ResponseEntity<byte[]> bundle() {
        List<Signature> items = service.getAllSignatures();
        int count = items.size();

        // --- manifest.txt ---
        List<String> lines = service.guidWithSignatureBase64(items);
        StringBuilder manifestTxt = new StringBuilder();
        manifestTxt.append(count).append("\n");              // 2.1 count
        lines.forEach(l -> manifestTxt.append(l).append("\n")); // 2.2 GUID:signature

        // ЭЦП манифеста на основе (count + все строки)
        String toSign = manifestTxt.toString();
        String manifestSigB64 = signing.signString(toSign);  // 2.3 ЭЦП
        manifestTxt.append("MANIFEST_SIG:").append(manifestSigB64).append("\n");

        byte[] manifestBytes = manifestTxt.toString().getBytes(StandardCharsets.UTF_8);


        byte[] dataBytes = SignatureBytes.buildDataBin(items);


        String boundary = "----AVBOUND-" + UUID.randomUUID();
        byte[] part1Header = (
                "--" + boundary + "\r\n" +
                        "Content-Type: text/plain; charset=utf-8\r\n" +
                        "Content-Disposition: attachment; filename=manifest.txt\r\n\r\n"
        ).getBytes(StandardCharsets.UTF_8);
        byte[] part2Header = (
                "\r\n--" + boundary + "\r\n" +
                        "Content-Type: application/octet-stream\r\n" +
                        "Content-Disposition: attachment; filename=data.bin\r\n\r\n"
        ).getBytes(StandardCharsets.UTF_8);
        byte[] end = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8);

        ByteBuffer bb = ByteBuffer.allocate(
                part1Header.length + manifestBytes.length +
                        part2Header.length + dataBytes.length + end.length
        );
        bb.put(part1Header);
        bb.put(manifestBytes);
        bb.put(part2Header);
        bb.put(dataBytes);
        bb.put(end);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "multipart/mixed; boundary=" + boundary)
                .body(bb.array());
    }
}
