package com.antivirus.server.services;

import com.antivirus.server.models.Signature;
import com.antivirus.server.models.Signature.Status;
import com.antivirus.server.models.SignatureAudit;
import com.antivirus.server.models.SignatureAudit.ChangeType;
import com.antivirus.server.repository.SignatureAuditRepository;
import com.antivirus.server.repository.SignatureRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class SignatureService {

    private final SignatureRepository repo;
    private final SignatureAuditRepository auditRepo;
    private final ManifestSigningService signing;
    private final ObjectMapper mapper;

    public SignatureService(SignatureRepository repo,
                            SignatureAuditRepository auditRepo,
                            ManifestSigningService signing,
                            ObjectMapper mapper) {
        this.repo = repo;
        this.auditRepo = auditRepo;
        this.signing = signing;
        this.mapper = mapper;
    }

    /** Основной список для API/манифеста: только ACTIVE */
    @Transactional(readOnly = true)
    public List<Signature> getAllSignatures() {
        return repo.findAllByStatus(Signature.Status.ACTIVE);
    }

    @Transactional(readOnly = true)
    public List<Signature> getAllActive() { return getAllSignatures(); }

    /** Дата релиза баз */
    @Transactional(readOnly = true)
    public OffsetDateTime getReleaseDate() {
        var d = repo.findLastReleaseDate();
        return d != null ? d : OffsetDateTime.now();
    }

    @Transactional(readOnly = true)
    public List<Signature> findByUpdatedBetween(OffsetDateTime from, OffsetDateTime to) {
        return repo.findAllByUpdatedAtBetweenAndStatusNot(from, to, Status.DELETED);
    }

    @Transactional(readOnly = true)
    public Optional<Signature> get(UUID id) { return repo.findById(id); }

    /** Создание + ЭЦП + аудит */
    @Transactional
    public Signature create(Signature s, String changedBy) {
        s.setStatus(Status.ACTIVE);
        s.setAvRecordSignature(signRecord(s));
        var saved = repo.save(s);
        audit(saved, null, ChangeType.CREATE, changedBy);
        return saved;
    }


    @Transactional
    public Signature update(UUID id, Signature patch, String changedBy) {
        return repo.findById(id).map(ex -> {
            String oldJson = toJson(ex);

            ex.setName(patch.getName());
            ex.setObjectType(patch.getObjectType());
            ex.setObjectSignaturePrefix(patch.getObjectSignaturePrefix());
            ex.setObjectSignatureLength(patch.getObjectSignatureLength());
            ex.setObjectSignature(patch.getObjectSignature());
            ex.setOffsetBegin(patch.getOffsetBegin());
            ex.setOffsetEnd(patch.getOffsetEnd());
            ex.setDescription(patch.getDescription());
            ex.setStatus(Status.ACTIVE);

            ex.setAvRecordSignature(signRecord(ex)); // переподписать
            var saved = repo.save(ex);

            audit(saved, oldJson, ChangeType.UPDATE, changedBy);
            return saved;
        }).orElseThrow(() -> new IllegalArgumentException("Signature not found: " + id));
    }


    @Transactional
    public void softDelete(UUID id, String changedBy) {
        repo.findById(id).ifPresent(ex -> {
            String oldJson = toJson(ex);
            ex.setStatus(Status.DELETED);
            repo.save(ex);
            audit(ex, oldJson, ChangeType.DELETE, changedBy);
        });
    }


    @Transactional
    public void saveVerifyResult(UUID id, boolean ok) {
        repo.findById(id).ifPresent(ex -> {
            audit(ex, null, ok ? ChangeType.VERIFY_OK : ChangeType.VERIFY_FAIL, "verifier");
        });
    }


    @Transactional
    public List<Signature> loadFromResourceAndSave(String resourcePath) throws Exception {
        var is = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath);
        if (is == null) throw new IllegalArgumentException("Resource not found: " + resourcePath);

        List<Signature> items = mapper.readValue(is, new TypeReference<List<Signature>>() {});
        for (Signature s : items) {
            if (s.getId() == null) s.setId(UUID.randomUUID());
            s.setStatus(Status.ACTIVE);
            s.setAvRecordSignature(signRecord(s));
        }
        return repo.saveAll(items);
    }


    @Transactional(readOnly = true)
    public String exportAllAsJson() {
        try {
            return mapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(getAllSignatures());
        } catch (Exception e) {
            throw new RuntimeException("JSON export failed", e);
        }
    }


    @Transactional
    public int resignAll() {
        var all = repo.findAll();
        for (var s : all) {
            s.setAvRecordSignature(signRecord(s));
            repo.save(s);
        }
        return all.size();
    }



    private byte[] signRecord(Signature s) {
        try {
            var pk = signing.loadPrivateKeyForSigning();
            var sig = java.security.Signature.getInstance("SHA256withRSA");
            sig.initSign(pk);
            sig.update(SignatureBytes.buildRecordBytes(s)); // бинарный образ записи
            return sig.sign();
        } catch (Exception e) {
            throw new RuntimeException("Cannot sign record " + s.getId(), e);
        }
    }

    private void audit(Signature s, String oldJson, ChangeType type, String by) {
        var a = new SignatureAudit();
        a.setSignatureId(s.getId());
        a.setChangedBy(by);
        a.setChangeType(type);
        a.setOldJson(oldJson);
        a.setNewJson(toJson(s));
        auditRepo.save(a);
    }

    private String toJson(Object o) {
        try { return mapper.writeValueAsString(o); }
        catch (Exception e) { return "{}"; }
    }


    @Transactional(readOnly = true)
    public List<String> guidWithSignatureBase64(List<Signature> items) {
        return items.stream()
                .map(s -> s.getId() + ":" + Base64.getEncoder().encodeToString(
                        s.getAvRecordSignature() == null ? new byte[0] : s.getAvRecordSignature()))
                .toList();
    }

    @Transactional(readOnly = true)
    public List<Signature> getAllIncludingDeleted() {
        return repo.findAll();
    }
}
