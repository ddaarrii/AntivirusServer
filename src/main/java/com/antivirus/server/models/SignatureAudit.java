package com.antivirus.server.models;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "signature_audit")
public class SignatureAudit {

    public enum ChangeType { CREATE, UPDATE, DELETE, VERIFY_OK, VERIFY_FAIL }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "signature_id", columnDefinition = "uuid", nullable = false)
    private UUID signatureId;

    @Enumerated(EnumType.STRING)
    @Column(name = "change_type", nullable = false, length = 16)
    private ChangeType changeType;

    @Column(name = "changed_at", nullable = false)
    private OffsetDateTime changedAt = OffsetDateTime.now();

    @Column(name = "changed_by", length = 64)
    private String changedBy;

    @Lob
    @Column(name = "old_json")
    private String oldJson;

    @Lob
    @Column(name = "new_json")
    private String newJson;

    // getters/setters
    public Long getId() { return id; }

    public UUID getSignatureId() { return signatureId; }
    public void setSignatureId(UUID signatureId) { this.signatureId = signatureId; }

    public ChangeType getChangeType() { return changeType; }
    public void setChangeType(ChangeType changeType) { this.changeType = changeType; }

    public OffsetDateTime getChangedAt() { return changedAt; }
    public void setChangedAt(OffsetDateTime changedAt) { this.changedAt = changedAt; }

    public String getChangedBy() { return changedBy; }
    public void setChangedBy(String changedBy) { this.changedBy = changedBy; }

    public String getOldJson() { return oldJson; }
    public void setOldJson(String oldJson) { this.oldJson = oldJson; }

    public String getNewJson() { return newJson; }
    public void setNewJson(String newJson) { this.newJson = newJson; }
}
