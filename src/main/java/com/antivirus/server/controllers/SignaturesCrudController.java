package com.antivirus.server.controllers;

import com.antivirus.server.models.Signature;
import com.antivirus.server.services.SignatureService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/signatures")
public class SignaturesCrudController {

    private final SignatureService service;

    public SignaturesCrudController(SignatureService service) {
        this.service = service;
    }

    @GetMapping
    public List<Signature> getAll() {
        // можно вызывать и getAllActive(), т.к. теперь есть алиас
        return service.getAllSignatures();
    }

    @GetMapping("/search")
    public List<Signature> searchByDate(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) OffsetDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) OffsetDateTime to) {
        return service.findByUpdatedBetween(from, to);
    }

    @PostMapping
    public ResponseEntity<Signature> create(@RequestBody Signature s,
                                            @RequestHeader(value = "X-User", required = false) String who) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(service.create(s, who == null ? "api" : who));
    }

    @PutMapping("/{id}")
    public Signature update(@PathVariable UUID id,
                            @RequestBody Signature s,
                            @RequestHeader(value = "X-User", required = false) String who) {
        return service.update(id, s, who == null ? "api" : who);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> softDelete(@PathVariable UUID id,
                                           @RequestHeader(value = "X-User", required = false) String who) {
        service.softDelete(id, who == null ? "api" : who);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Signature> getOne(@PathVariable UUID id) {
        return service.get(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /** Полный список, включая DELETED — удобно для диагностики */
    @GetMapping("/all")
    public List<Signature> getAllIncludingDeleted() {
        return service.getAllIncludingDeleted();
    }

    /** Выгрузка JSON файлом (как просили для Postman) */
    @GetMapping(value = "/download", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> downloadJson() {
        String json = service.exportAllAsJson();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signatures.json")
                .body(json.getBytes(StandardCharsets.UTF_8));
    }
}
