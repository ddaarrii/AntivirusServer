package com.antivirus.server.services;

import com.antivirus.server.models.Signature;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.List;

public final class SignatureBytes {

    private SignatureBytes() {}


    public static byte[] buildRecordBytes(Signature s) {
        byte[] nameBytes = (s.getName() == null)
                ? new byte[0]
                : s.getName().getBytes(StandardCharsets.US_ASCII);

        long prefix = parsePrefix8(s.getObjectSignaturePrefix());
        byte[] sigBytes = parseSignatureBytes(s.getObjectSignature());
        int sigLen = (s.getObjectSignatureLength() == null)
                ? sigBytes.length
                : s.getObjectSignatureLength();

        long offBegin = (s.getOffsetBegin() == null) ? 0L : s.getOffsetBegin();
        long offEnd   = (s.getOffsetEnd()   == null) ? 0L : s.getOffsetEnd();
        byte objType  = (byte) mapType(s.getObjectType());

        ByteBuffer bb = ByteBuffer.allocate(
                4 + nameBytes.length + 8 + 4 + sigBytes.length + 8 + 8 + 1
        ).order(ByteOrder.LITTLE_ENDIAN);

        // ObjectName
        bb.putInt(nameBytes.length);
        bb.put(nameBytes);

        // ObjectSignaturePrefix / Length / Signature
        bb.putLong(prefix);
        bb.putInt(sigLen);
        bb.put(sigBytes);

        // OffsetBegin / OffsetEnd / ObjectType
        bb.putLong(offBegin);
        bb.putLong(offEnd);
        bb.put(objType);

        return bb.array();
    }


    public static byte[] buildDataBin(List<Signature> items) {
        // оценим итоговый размер
        int total = 0;
        byte[][] chunks = new byte[items.size()][];
        for (int i = 0; i < items.size(); i++) {
            byte[] rec = buildRecordBytes(items.get(i));
            chunks[i] = rec;
            total += rec.length;
        }
        ByteBuffer out = ByteBuffer.allocate(total);
        for (byte[] c : chunks) out.put(c);
        return out.array();
    }


    private static long parsePrefix8(String hex) {
        if (hex == null || hex.isBlank()) return 0L;
        String clean = hex.replaceAll("[^0-9A-Fa-f]", "");
        if (clean.length() > 16) clean = clean.substring(0, 16); // 8 байт = 16 hex-символов
        if (clean.isEmpty()) return 0L;
        return new java.math.BigInteger(clean, 16).longValue();
    }


    private static byte[] parseSignatureBytes(String hex) {
        if (hex == null || hex.isBlank()) return new byte[0];
        String clean = hex.replaceAll("[^0-9A-Fa-f]", "");
        int len = clean.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }


    private static int mapType(Signature.ObjectType t) {
        if (t == null) return 0;
        return switch (t) {
            case PE -> 0;
            case JAVA -> 1;
        };
    }
}
