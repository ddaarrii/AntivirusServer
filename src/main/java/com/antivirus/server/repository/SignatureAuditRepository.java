package com.antivirus.server.repository;

import com.antivirus.server.models.SignatureAudit;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SignatureAuditRepository extends JpaRepository<SignatureAudit, Long> { }
