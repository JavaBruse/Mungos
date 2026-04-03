package com.JavaBruse.core.sniffer.converters;

import com.JavaBruse.core.sniffer.domain.DTO.JA4EntryDTO;
import com.JavaBruse.core.sniffer.domain.DTO.SNIEntryDTO;
import com.JavaBruse.proto.JA4Entry;
import com.JavaBruse.proto.SNIEntry;

public class Ja4SniConverter {

    public static JA4EntryDTO toDTO(JA4Entry entry) {
        return new JA4EntryDTO(
                entry.getId(),
                entry.getFingerprint(),
                entry.getApplication(),
                entry.getLibrary(),
                entry.getDevice(),
                entry.getOs(),
                entry.getObservationCount(),
                entry.getVerified(),
                entry.getFingerprintType(),
                entry.getSessionKey(),
                entry.getUpdatedAt()
        );
    }

    public static JA4Entry toProto(JA4EntryDTO dto) {
        return JA4Entry.newBuilder()
                .setId(dto.getId())
                .setFingerprint(dto.getFingerprint())
                .setApplication(dto.getApplication())
                .setLibrary(dto.getLibrary())
                .setDevice(dto.getDevice())
                .setOs(dto.getOs())
                .setObservationCount(dto.getObservationCount())
                .setVerified(dto.isVerified())
                .setFingerprintType(dto.getFingerprintType())
                .setSessionKey(dto.getSessionKey())
                .setUpdatedAt(dto.getUpdatedAt())
                .build();
    }

    public static SNIEntryDTO toDTO(SNIEntry entry) {
        return new SNIEntryDTO(
                entry.getId(),
                entry.getService(),
                entry.getSni(),
                entry.getOccurrenceCount(),
                entry.getFirstSeen(),
                entry.getLastSeen(),
                entry.getSessionKey()
        );
    }

    public static SNIEntry toProto(SNIEntryDTO dto) {
        return SNIEntry.newBuilder()
                .setId(dto.getId())
                .setService(dto.getService())
                .setSni(dto.getSni())
                .setOccurrenceCount(dto.getOccurrenceCount())
                .setFirstSeen(dto.getFirstSeen())
                .setLastSeen(dto.getLastSeen())
                .setSessionKey(dto.getSessionKey())
                .build();
    }
}
