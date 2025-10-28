package com.antivirus.server.services;

import com.antivirus.server.models.Signature;
import com.antivirus.server.repository.SignatureRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.util.List;

@Service
public class SignatureLoader {
    @Autowired
    private SignatureRepository signatureRepository;

    @PostConstruct
    public void loadSignatures() {
        try {
            if (signatureRepository.count() > 0) {
                System.out.println("Signatures already present, skip bootstrap.");
                return;
            }
            InputStream inputStream = new ClassPathResource("signatures.json").getInputStream();
            ObjectMapper mapper = new ObjectMapper();
            List<Signature> signatures = mapper.readValue(inputStream, new TypeReference<List<Signature>>() {});
            signatureRepository.saveAll(signatures);
            System.out.println("Сигнатуры загружены: " + signatures.size());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
