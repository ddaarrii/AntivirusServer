package com.antivirus.server.controllers;

import com.antivirus.server.services.SignatureService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
public class AdminController {
    private final SignatureService signatureService;
    public AdminController(SignatureService signatureService) { this.signatureService = signatureService; }


    @PostMapping("/signatures/resign")
    public ResponseEntity<String> resignAll() {
        int n = signatureService.resignAll();
        return ResponseEntity.ok("Resigned signatures: " + n);
    }
}
