package com.antivirus.server.repository;

import com.antivirus.server.models.Signature;
import com.antivirus.server.models.Signature.Status;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public interface SignatureRepository extends JpaRepository<Signature, UUID> {

    @Query("select max(s.updatedAt) from Signature s where s.status <> 'DELETED'")
    OffsetDateTime findLastReleaseDate();

    List<Signature> findAllByStatus(Status status);

    List<Signature> findAllByUpdatedAtBetweenAndStatusNot(OffsetDateTime from, OffsetDateTime to, Status status);
}
