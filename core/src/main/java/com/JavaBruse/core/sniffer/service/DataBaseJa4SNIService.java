package com.JavaBruse.core.sniffer.service;

import com.JavaBruse.core.exaption.ConnectionException;
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
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

        log.info("Updating JA4 entry: {}", entry.getId());

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

        log.info("Updating SNI entry: {}", entry.getId());

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
        log.info("Starting JA4 sync for {} sniffers", allSniffers.size());
        Map<String, JA4Entry> masterDatabase = new HashMap<>();

        for (SnifferEntity sniffer : allSniffers) {
            try {
                log.debug("Collecting from sniffer: {}", sniffer.getId());
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

        log.info("Master database built with {} unique entries", masterDatabase.size());

        // Рассылаем всем
        List<JA4Entry> masterList = new ArrayList<>(masterDatabase.values());
        for (SnifferEntity sniffer : allSniffers) {
            try {
                uploadJA4Database(sniffer.getId(), masterList);
                log.debug("Updated sniffer: {}", sniffer.getId());
            } catch (Exception e) {
                log.error("Failed to update sniffer: {}", sniffer.getId(), e);
            }
        }

        log.info("JA4 sync completed for {} sniffers", allSniffers.size());
    }

    public void syncSNIDatabases() {
        List<SnifferEntity> allSniffers = snifferRepository.findByDeletedFalse();
        if (allSniffers.size() <= 1) return;
        log.info("Starting SNI sync for {} sniffers", allSniffers.size());
        Map<String, SNIEntry> masterDatabase = new HashMap<>();

        for (SnifferEntity sniffer : allSniffers) {
            try {
                log.debug("Collecting from sniffer: {}", sniffer.getId());
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

        log.info("Master database built with {} unique entries", masterDatabase.size());
        List<SNIEntry> masterList = new ArrayList<>(masterDatabase.values());
        for (SnifferEntity sniffer : allSniffers) {
            try {
                uploadSNIDatabase(sniffer.getId(), masterList);
                log.debug("Updated sniffer: {}", sniffer.getId());
            } catch (Exception e) {
                log.error("Failed to update sniffer: {}", sniffer.getId(), e);
            }
        }

        log.info("SNI sync completed for {} sniffers", allSniffers.size());
    }

    private SNIEntry mergeSNIEntries(SNIEntry e1, SNIEntry e2) {
        if (e1.getLastSeen() >= e2.getLastSeen()) {
            return e1;
        }
        return e2;
    }

    private JA4Entry mergeJA4Entries(JA4Entry e1, JA4Entry e2) {
        if (e1.getUpdatedAt() >= e2.getUpdatedAt()) {
            return e1;
        }
        return e2;
    }

    private List<JA4Entry> downloadJA4Database(String id) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));

        log.info("Downloading JA4 database from sniffer: {}", id);

        byte[] compressedData = retryPolicy.executeWithRetry(
                RetryStrategy.defaultPingStrategy(),
                () -> ja4DatabaseCommand.downloadDatabase(sniffer),
                this::isRetryableError,
                "download-ja4-" + id
        );

        try {
            JA4EntryList entryList = ProtoCompressor.decompressProto(compressedData, JA4EntryList.class);
            log.info("Downloaded {} JA4 entries", entryList.getEntriesCount());
            return entryList.getEntriesList();
        } catch (IOException e) {
            log.error("Failed to decompress JA4 database", e);
            throw new RuntimeException("Failed to decompress JA4 database", e);
        }
    }

    private void uploadJA4Database(String id, List<JA4Entry> entries) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));

        log.info("Uploading JA4 database to sniffer: {}, entries: {}", id, entries.size());

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

        log.info("Downloading SNI database from sniffer: {}", id);

        byte[] compressedData = retryPolicy.executeWithRetry(
                RetryStrategy.defaultPingStrategy(),
                () -> sniDatabaseCommand.downloadDatabase(sniffer),
                this::isRetryableError,
                "download-sni-" + id
        );

        try {
            SNIEntryList entryList = ProtoCompressor.decompressProto(compressedData, SNIEntryList.class);
            log.info("Downloaded {} SNI entries", entryList.getEntriesCount());
            return entryList.getEntriesList();
        } catch (IOException e) {
            log.error("Failed to decompress SNI database", e);
            throw new RuntimeException("Failed to decompress SNI database", e);
        }
    }

    private void uploadSNIDatabase(String id, List<SNIEntry> entries) {
        SnifferEntity sniffer = snifferRepository.findById(id)
                .orElseThrow(() -> new ConnectionException("Sniffer not found: " + id));

        log.info("Uploading SNI database to sniffer: {}, entries: {}", id, entries.size());

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
}