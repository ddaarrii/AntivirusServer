package com.antivirus.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class AntivirusServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(AntivirusServerApplication.class, args);
    }
}
