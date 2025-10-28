/**

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
import org.springframework.web.bind.annotation.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api") // общий префикс
public class SignatureController {

    private final SignatureService signatureService;
    private final ManifestSigningService signingService;

    public SignatureController(SignatureService signatureService,
                               ManifestSigningService signingService) {
        this.signatureService = signatureService;
        this.signingService = signingService;
    }

    /** JSON-список всех сигнатур (как раньше показывала коллекция в Postman) */
/**
    @GetMapping("/signatures")
    public List<Signature> getAllSignatures() {
        return signatureService.getAllSignatures();
    }

    /** Скачивание "старого" JSON (как было в коллекции) */
/**
    @GetMapping(value = "/signatures/download", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> downloadJson() {
        String json = signatureService.exportAllAsJson();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signatures.json")
                .body(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Манифест: возвращаем заголовок + записи (в JSON) — удобно глазом проверить. */
/**
    @GetMapping("/manifest")
    public ManifestDto getManifest() {
        List<Signature> records = signatureService.getAllSignatures();
        OffsetDateTime date = signatureService.getReleaseDate();
        ManifestHeaderDto header = signingService.buildSignedHeader(date, records.size());
        return new ManifestDto(header, records);
    }

    /** Сертификат сервера в PEM (для Postman/проверок) */
/**
    @GetMapping(value = "/manifest/cert", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> getCertificatePem() {
        var cert = signingService.getServerCertificate();
        return ResponseEntity.ok(PemUtil.toPem(cert));
    }

    /**
     * Отдаём multipart/mixed:
     *  - part "manifest.txt" — текстовый манифест (count, GUID:signature, подпись);
     *  - part "data.bin"     — бинарные записи сигнатур строго по ТЗ.
     */
/**
    @GetMapping(value = "/manifest/export", produces = "multipart/mixed")
    public ResponseEntity<byte[]> exportManifestAndData() {
        try {
            var all = signatureService.getAllSignatures();
            var header = signingService.buildSignedHeader(signatureService.getReleaseDate(), all.size());

            // 1) manifest.txt
            StringBuilder sb = new StringBuilder();
            sb.append(all.size()).append("\n");
            for (Signature s : all) {
                // GUID: digital_signature (пока цифровая подпись записи опциональна — оставим заглушку)
                String guid = s.getId().toString();
                // если добавишь AvRecordSignature в модель: String ds = Base64.getEncoder().encodeToString(s.getAvRecordSignature());
                String ds = ""; // заглушка
                sb.append(guid).append(":").append(ds).append("\n");
            }
            // Подпись манифеста по пунктам 2.1 + 2.2
            String manifestCore = sb.toString();
            String manifestSigB64 = signingService.signString(manifestCore);
            sb.append("MANIFEST_SIG=").append(manifestSigB64).append("\n");
            byte[] manifestBytes = sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);

            // 2) data.bin — бинарные записи по ТЗ
            int totalSize = 0;
            byte[][] blocks = new byte[all.size()][];
            for (int i = 0; i < all.size(); i++) {
                blocks[i] = SignatureBytes.buildRecordBytes(all.get(i));
                totalSize += blocks[i].length;
            }
            ByteBuffer data = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN);
            for (byte[] b : blocks) data.put(b);
            byte[] dataBytes = data.array();

            // Сборка multipart/mixed вручную
            String boundary = "----AVBoundary" + UUID.randomUUID();
            byte[] body = MultipartBuilder
                    .boundary(boundary)
                    .part("manifest.txt", "text/plain; charset=utf-8", manifestBytes)
                    .part("data.bin", "application/octet-stream", dataBytes)
                    .build();

            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType("multipart/mixed; boundary=" + boundary))
                    .body(body);

        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(
                    ("Export error: " + e.getMessage()).getBytes());
        }
    }

    /** (необязательно) пример загрузки исходного JSON из ресурсов в БД */
/**
    @PostMapping("/manifest/load")
    public ResponseEntity<String> loadInitial() {
        try {
            signatureService.loadFromResourceAndSave("signatures.json");
            return ResponseEntity.ok("Loaded");
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }

    /* Вспомогательный построитель multipart/mixed */
/**
    static final class MultipartBuilder {
        private final String boundary;
        private final String CRLF = "\r\n";
        private final StringBuilder head = new StringBuilder();
        private final java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();

        private MultipartBuilder(String boundary) { this.boundary = boundary; }

        public static MultipartBuilder boundary(String b) {
            return new MultipartBuilder(b);
        }

        public MultipartBuilder part(String filename, String contentType, byte[] content) {
            try {
                head.append("--").append(boundary).append(CRLF);
                head.append("Content-Disposition: form-data; name=\"file\"; filename=\"")
                        .append(filename).append("\"").append(CRLF);
                head.append("Content-Type: ").append(contentType).append(CRLF);
                head.append(CRLF);
                body.write(head.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                body.write(content);
                body.write(CRLF.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                head.setLength(0);
                return this;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public byte[] build() {
            try {
                String end = "--" + boundary + "--\r\n";
                body.write(end.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                return body.toByteArray();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}

*/