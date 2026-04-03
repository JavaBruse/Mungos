package com.JavaBruse.core.sniffer.service;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.sniffer.converters.Ja4SniConverter;
import com.JavaBruse.core.sniffer.domain.DTO.JA4EntryDTO;
import com.JavaBruse.core.sniffer.domain.DTO.SNIEntryDTO;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.grpc.ProtoCompressor;
import com.JavaBruse.core.sniffer.grpc.command.HashTableCommand;
import com.JavaBruse.core.sniffer.grpc.command.JA4DatabaseCommand;
import com.JavaBruse.core.sniffer.grpc.command.SNIDatabaseCommand;
import com.JavaBruse.core.sniffer.grpc.retry.RetryPolicy;
import com.JavaBruse.core.sniffer.grpc.retry.RetryStrategy;
import com.JavaBruse.core.sniffer.repository.SnifferRepository;
import com.JavaBruse.proto.*;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Service;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class DataBaseJa4SNIService {

    private final SnifferRepository snifferRepository;
    private final JA4DatabaseCommand ja4DatabaseCommand;
    private final SNIDatabaseCommand sniDatabaseCommand;
    private final HashTableCommand hashTableCommand;
    private final RetryPolicy retryPolicy;

    public HashTable getDatabaseHashes(String snifferId) {
        SnifferEntity sniffer = snifferRepository.findById(snifferId)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + snifferId));

        return retryPolicy.executeWithRetry(
                RetryStrategy.defaultPingStrategy(),
                () -> hashTableCommand.execute(sniffer, null),
                this::isRetryableError,
                "hashes-" + snifferId
        );
    }

    public JA4Entry updateOrSaveJA4Entry(String id, JA4Entry entry) {
        SnifferEntity sniffer = snifferRepository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));
        return retryPolicy.executeWithRetry(
                RetryStrategy.defaultPingStrategy(),
                () -> ja4DatabaseCommand.updateOrSaveEntry(sniffer, entry),
                this::isRetryableError,
                "update-ja4-" + id
        );
    }

    public SNIEntry updateOrSaveSNIEntry(String id, SNIEntry entry) {
        SnifferEntity sniffer = snifferRepository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));
        return retryPolicy.executeWithRetry(
                RetryStrategy.defaultPingStrategy(),
                () -> sniDatabaseCommand.updateOrSaveEntry(sniffer, entry),
                this::isRetryableError,
                "update-sni-" + id
        );
    }

    public void syncJA4Databases() {
        List<SnifferEntity> allSniffers = snifferRepository.findByDeletedFalse();
        if (allSniffers.size() <= 1) return;
        Map<String, JA4Entry> masterDatabase = new HashMap<>();
        for (SnifferEntity sniffer : allSniffers) {
            try {
                List<JA4Entry> snifferEntries = downloadJA4Database(sniffer.getId());

                for (JA4Entry entry : snifferEntries) {
                    String key = entry.getFingerprint() + ":" + entry.getFingerprintType();
                    JA4Entry existing = masterDatabase.get(key);

                    if (existing == null || entry.getUpdatedAt() > existing.getUpdatedAt()) {
                        masterDatabase.put(key, entry);
                    }
                }
            } catch (Exception e) {
                log.error("Failed to collect from sniffer: {}", sniffer.getId(), e);
            }
        }
        List<JA4Entry> masterList = new ArrayList<>(masterDatabase.values());
        for (SnifferEntity sniffer : allSniffers) {
            try {
                uploadJA4Database(sniffer.getId(), masterList);
            } catch (Exception e) {
                log.error("Failed to update sniffer: {}", sniffer.getId(), e);
            }
        }
    }

    public void syncSNIDatabases() {
        List<SnifferEntity> allSniffers = snifferRepository.findByDeletedFalse();
        if (allSniffers.size() <= 1) return;
        Map<String, SNIEntry> masterDatabase = new HashMap<>();

        for (SnifferEntity sniffer : allSniffers) {
            try {
                List<SNIEntry> snifferEntries = downloadSNIDatabase(sniffer.getId());

                for (SNIEntry entry : snifferEntries) {
                    String key = entry.getService() + ":" + entry.getSni();
                    SNIEntry existing = masterDatabase.get(key);

                    if (existing == null) {
                        masterDatabase.put(key, entry);
                    } else {
                        String service = existing.getService();
                        if (!entry.getService().equals("unknown")) {
                            service = entry.getService();
                        }

                        int count = Math.max(existing.getOccurrenceCount(), entry.getOccurrenceCount());
                        long firstSeen = Math.min(existing.getFirstSeen(), entry.getFirstSeen());
                        long lastSeen = Math.max(existing.getLastSeen(), entry.getLastSeen());

                        SNIEntry merged = entry.toBuilder()
                                .setService(service)
                                .setOccurrenceCount(count)
                                .setFirstSeen(firstSeen)
                                .setLastSeen(lastSeen)
                                .build();

                        masterDatabase.put(key, merged);
                    }
                }
            } catch (Exception e) {
                log.error("Failed to collect from sniffer: {}", sniffer.getId(), e);
            }
        }

        List<SNIEntry> masterList = new ArrayList<>(masterDatabase.values());
        for (SnifferEntity sniffer : allSniffers) {
            try {
                uploadSNIDatabase(sniffer.getId(), masterList);
                log.debug("Updated sniffer: {}", sniffer.getId());
            } catch (Exception e) {
                log.error("Failed to update sniffer: {}", sniffer.getId(), e);
            }
        }

    }

    private List<JA4Entry> downloadJA4Database(String id) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));

        byte[] compressedData = retryPolicy.executeWithRetry(
                RetryStrategy.defaultPingStrategy(),
                () -> ja4DatabaseCommand.downloadDatabase(sniffer),
                this::isRetryableError,
                "download-ja4-" + id
        );

        try {
            JA4EntryList entryList = ProtoCompressor.decompressProto(compressedData, JA4EntryList.class);
            return entryList.getEntriesList();
        } catch (IOException e) {
            log.error("Failed to decompress JA4 database", e);
            throw new RuntimeException("Failed to decompress JA4 database", e);
        }
    }

    private void uploadJA4Database(String id, List<JA4Entry> entries) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));
        try {
            JA4EntryList entryList = JA4EntryList.newBuilder()
                    .addAllEntries(entries)
                    .build();

            byte[] compressedData = ProtoCompressor.compressProto(entryList);

            retryPolicy.executeWithRetry(
                    RetryStrategy.defaultPingStrategy(),
                    () -> ja4DatabaseCommand.uploadDatabase(sniffer, compressedData),
                    this::isRetryableError,
                    "upload-ja4-" + id
            );

        } catch (IOException e) {
            log.error("Failed to compress JA4 database", e);
            throw new RuntimeException("Failed to compress JA4 database", e);
        }
    }

    private List<SNIEntry> downloadSNIDatabase(String id) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));
        byte[] compressedData = retryPolicy.executeWithRetry(
                RetryStrategy.defaultPingStrategy(),
                () -> sniDatabaseCommand.downloadDatabase(sniffer),
                this::isRetryableError,
                "download-sni-" + id
        );

        try {
            SNIEntryList entryList = ProtoCompressor.decompressProto(compressedData, SNIEntryList.class);
            return entryList.getEntriesList();
        } catch (IOException e) {
            log.error("Failed to decompress SNI database", e);
            throw new RuntimeException("Failed to decompress SNI database", e);
        }
    }

    private void uploadSNIDatabase(String id, List<SNIEntry> entries) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));
        try {
            SNIEntryList entryList = SNIEntryList.newBuilder()
                    .addAllEntries(entries)
                    .build();

            byte[] compressedData = ProtoCompressor.compressProto(entryList);

            retryPolicy.executeWithRetry(
                    RetryStrategy.defaultPingStrategy(),
                    () -> sniDatabaseCommand.uploadDatabase(sniffer, compressedData),
                    this::isRetryableError,
                    "upload-sni-" + id
            );

        } catch (IOException e) {
            log.error("Failed to compress SNI database", e);
            throw new RuntimeException("Failed to compress SNI database", e);
        }
    }

    private boolean isRetryableError(Exception e) {
        if (e instanceof ConnectionException) {
            return true;
        }
        if (e instanceof StatusRuntimeException) {
            Status.Code code = ((StatusRuntimeException) e).getStatus().getCode();
            return code == Status.Code.UNAVAILABLE || code == Status.Code.UNAUTHENTICATED;
        }
        return false;
    }

    public byte[] exportJA4DatabaseToExcel(String snifferId) {
        List<JA4Entry> entries = downloadJA4Database(snifferId);
        List<JA4EntryDTO> dtos = entries.stream()
                .map(Ja4SniConverter::toDTO)
                .collect(Collectors.toList());

        Workbook workbook = new XSSFWorkbook();
        Sheet sheet = workbook.createSheet("JA4 Database");

        Row header = sheet.createRow(0);
        String[] columns = {"id", "fingerprint", "application", "library", "device", "os", "observationCount", "verified", "fingerprintType", "sessionKey", "updatedAt"};
        for (int i = 0; i < columns.length; i++) {
            header.createCell(i).setCellValue(columns[i]);
        }

        int rowNum = 1;
        for (JA4EntryDTO dto : dtos) {
            Row row = sheet.createRow(rowNum++);
            row.createCell(0).setCellValue(dto.getId());
            row.createCell(1).setCellValue(dto.getFingerprint());
            row.createCell(2).setCellValue(dto.getApplication());
            row.createCell(3).setCellValue(dto.getLibrary());
            row.createCell(4).setCellValue(dto.getDevice());
            row.createCell(5).setCellValue(dto.getOs());
            row.createCell(6).setCellValue(dto.getObservationCount());
            row.createCell(7).setCellValue(dto.isVerified());
            row.createCell(8).setCellValue(dto.getFingerprintType());
            row.createCell(9).setCellValue(dto.getSessionKey());
            row.createCell(10).setCellValue(dto.getUpdatedAt());
        }

        for (int i = 0; i < columns.length; i++) {
            sheet.autoSizeColumn(i);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            workbook.write(out);
            workbook.close();
        } catch (IOException e) {
            throw new RuntimeException("Failed to export JA4 to Excel", e);
        }
        return out.toByteArray();
    }

    public byte[] exportSNIDatabaseToExcel(String snifferId) {
        List<SNIEntry> entries = downloadSNIDatabase(snifferId);
        List<SNIEntryDTO> dtos = entries.stream()
                .map(Ja4SniConverter::toDTO)
                .collect(Collectors.toList());

        Workbook workbook = new XSSFWorkbook();
        Sheet sheet = workbook.createSheet("SNI Database");

        Row header = sheet.createRow(0);
        String[] columns = {"id", "service", "sni", "occurrenceCount", "firstSeen", "lastSeen", "sessionKey"};
        for (int i = 0; i < columns.length; i++) {
            header.createCell(i).setCellValue(columns[i]);
        }

        int rowNum = 1;
        for (SNIEntryDTO dto : dtos) {
            Row row = sheet.createRow(rowNum++);
            row.createCell(0).setCellValue(dto.getId());
            row.createCell(1).setCellValue(dto.getService());
            row.createCell(2).setCellValue(dto.getSni());
            row.createCell(3).setCellValue(dto.getOccurrenceCount());
            row.createCell(4).setCellValue(dto.getFirstSeen());
            row.createCell(5).setCellValue(dto.getLastSeen());
            row.createCell(6).setCellValue(dto.getSessionKey());
        }

        for (int i = 0; i < columns.length; i++) {
            sheet.autoSizeColumn(i);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            workbook.write(out);
            workbook.close();
        } catch (IOException e) {
            throw new RuntimeException("Failed to export SNI to Excel", e);
        }
        return out.toByteArray();
    }

    public void uploadJA4DatabaseFromExcel(String snifferId, byte[] excelBytes) {
        try (InputStream inputStream = new ByteArrayInputStream(excelBytes);
             Workbook workbook = new XSSFWorkbook(inputStream)) {

            Sheet sheet = workbook.getSheetAt(0);
            List<JA4EntryDTO> dtos = new ArrayList<>();

            for (int i = 1; i <= sheet.getLastRowNum(); i++) {
                Row row = sheet.getRow(i);
                if (row == null) continue;

                JA4EntryDTO dto = new JA4EntryDTO();
                dto.setId(getCellValue(row.getCell(0)));
                dto.setFingerprint(getCellValue(row.getCell(1)));
                dto.setApplication(getCellValue(row.getCell(2)));
                dto.setLibrary(getCellValue(row.getCell(3)));
                dto.setDevice(getCellValue(row.getCell(4)));
                dto.setOs(getCellValue(row.getCell(5)));
                dto.setObservationCount((int) getNumericCellValue(row.getCell(6)));
                dto.setVerified(Boolean.parseBoolean(getCellValue(row.getCell(7))));
                dto.setFingerprintType(getCellValue(row.getCell(8)));
                dto.setSessionKey(getCellValue(row.getCell(9)));
                dto.setUpdatedAt((long) getNumericCellValue(row.getCell(10)));
                dtos.add(dto);
            }

            List<JA4Entry> entries = dtos.stream()
                    .map(Ja4SniConverter::toProto)
                    .collect(Collectors.toList());
            uploadJA4Database(snifferId, entries);
        } catch (IOException e) {
            throw new RuntimeException("Failed to upload JA4 from Excel", e);
        }
    }

    public void uploadSNIDatabaseFromExcel(String snifferId, byte[] excelBytes) {
        try (InputStream inputStream = new ByteArrayInputStream(excelBytes);
             Workbook workbook = new XSSFWorkbook(inputStream)) {

            Sheet sheet = workbook.getSheetAt(0);
            List<SNIEntryDTO> dtos = new ArrayList<>();

            for (int i = 1; i <= sheet.getLastRowNum(); i++) {
                Row row = sheet.getRow(i);
                if (row == null) continue;

                SNIEntryDTO dto = new SNIEntryDTO();
                dto.setId(getCellValue(row.getCell(0)));
                dto.setService(getCellValue(row.getCell(1)));
                dto.setSni(getCellValue(row.getCell(2)));
                dto.setOccurrenceCount((int) getNumericCellValue(row.getCell(3)));
                dto.setFirstSeen((long) getNumericCellValue(row.getCell(4)));
                dto.setLastSeen((long) getNumericCellValue(row.getCell(5)));
                dto.setSessionKey(getCellValue(row.getCell(6)));
                dtos.add(dto);
            }

            List<SNIEntry> entries = dtos.stream()
                    .map(Ja4SniConverter::toProto)
                    .collect(Collectors.toList());
            uploadSNIDatabase(snifferId, entries);
        } catch (IOException e) {
            throw new RuntimeException("Failed to upload SNI from Excel", e);
        }
    }

    private String getCellValue(Cell cell) {
        if (cell == null) return "";
        switch (cell.getCellType()) {
            case STRING: return cell.getStringCellValue();
            case NUMERIC: return String.valueOf((long) cell.getNumericCellValue());
            case BOOLEAN: return String.valueOf(cell.getBooleanCellValue());
            default: return "";
        }
    }

    private double getNumericCellValue(Cell cell) {
        if (cell == null) return 0;
        switch (cell.getCellType()) {
            case NUMERIC: return cell.getNumericCellValue();
            case STRING:
                try {
                    return Double.parseDouble(cell.getStringCellValue());
                } catch (NumberFormatException e) {
                    return 0;
                }
            default: return 0;
        }
    }
}