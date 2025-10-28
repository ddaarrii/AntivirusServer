package com.antivirus.server.dto;

import com.antivirus.server.models.Signature;
import java.util.List;

public class ManifestDto {
    public ManifestHeaderDto header;
    public List<Signature> records;

    public ManifestDto(ManifestHeaderDto header, List<Signature> records) {
        this.header = header;
        this.records = records;
    }
}
