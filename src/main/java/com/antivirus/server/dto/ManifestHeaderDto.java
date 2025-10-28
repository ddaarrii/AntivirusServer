package com.antivirus.server.dto;

import java.time.OffsetDateTime;

public class ManifestHeaderDto {
    public String magicNumber;
    public OffsetDateTime releaseDate;
    public long count;
    public String headerSignature;

    public ManifestHeaderDto(String magicNumber, OffsetDateTime releaseDate, long count, String headerSignature) {
        this.magicNumber = magicNumber;
        this.releaseDate = releaseDate;
        this.count = count;
        this.headerSignature = headerSignature;
    }
}
