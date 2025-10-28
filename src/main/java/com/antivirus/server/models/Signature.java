package com.antivirus.server.models;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "signatures")
public class Signature {

    public enum Status { ACTIVE, DELETED }
    public enum ObjectType { PE, JAVA }

    @Id
    @Column(columnDefinition = "uuid")
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "object_type", nullable = false, length = 16)
    private ObjectType objectType = ObjectType.PE;

    @Column(name = "object_signature_prefix", length = 32)
    private String objectSignaturePrefix;

    @Column(name = "object_signature_length")
    private Integer objectSignatureLength;

    @Column(name = "object_signature", columnDefinition = "text")
    private String objectSignature;

    @Column(name = "offset_begin")
    private Long offsetBegin;

    @Column(name = "offset_end")
    private Long offsetEnd;

    @Column(columnDefinition = "text")
    private String description;

    /**
     * ЭЦП записи (AvRecordSignature) — реальные байты подписи.
     * ВАЖНО: храним как BYTEA, без @Lob, чтобы не использовать Large Object (OID).
     */
    @Column(name = "av_record_signature", columnDefinition = "bytea")
    private byte[] avRecordSignature;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Status status = Status.ACTIVE;

    /** Оптимистическая блокировка */
    @Version
    private Long version;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    public Signature() { this.id = UUID.randomUUID(); }

    @PrePersist
    public void prePersist() {
        var now = OffsetDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    public void preUpdate() { this.updatedAt = OffsetDateTime.now(); }

    // ---------- getters / setters ----------
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public ObjectType getObjectType() { return objectType; }
    public void setObjectType(ObjectType objectType) { this.objectType = objectType; }

    public String getObjectSignaturePrefix() { return objectSignaturePrefix; }
    public void setObjectSignaturePrefix(String objectSignaturePrefix) { this.objectSignaturePrefix = objectSignaturePrefix; }

    public Integer getObjectSignatureLength() { return objectSignatureLength; }
    public void setObjectSignatureLength(Integer objectSignatureLength) { this.objectSignatureLength = objectSignatureLength; }

    public String getObjectSignature() { return objectSignature; }
    public void setObjectSignature(String objectSignature) { this.objectSignature = objectSignature; }

    public Long getOffsetBegin() { return offsetBegin; }
    public void setOffsetBegin(Long offsetBegin) { this.offsetBegin = offsetBegin; }

    public Long getOffsetEnd() { return offsetEnd; }
    public void setOffsetEnd(Long offsetEnd) { this.offsetEnd = offsetEnd; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public byte[] getAvRecordSignature() { return avRecordSignature; }
    public void setAvRecordSignature(byte[] avRecordSignature) { this.avRecordSignature = avRecordSignature; }

    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }

    public Long getVersion() { return version; }
    public void setVersion(Long version) { this.version = version; }

    public OffsetDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(OffsetDateTime createdAt) { this.createdAt = createdAt; }

    public OffsetDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(OffsetDateTime updatedAt) { this.updatedAt = updatedAt; }
}
