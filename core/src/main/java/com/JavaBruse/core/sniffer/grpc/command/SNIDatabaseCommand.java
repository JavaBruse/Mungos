package com.JavaBruse.core.sniffer.grpc.command;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.proto.*;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;

@Slf4j
@Component
public class SNIDatabaseCommand {

    private static final int CHUNK_SIZE = 32 * 1024;
    private final SessionManager sessionManager;

    public SNIDatabaseCommand(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    public byte[] downloadDatabase(SnifferEntity sniffer) {
        return sessionManager.executeWithSession(sniffer, session -> {
            SNIDataChunkRequest protoRequest = SNIDataChunkRequest.newBuilder()
                    .setSessionKey(session.getSessionKey())
                    .build();

            try {
                Iterator<SNIDataChunk> chunks = sessionManager.getStub(session)
                        .downloadSNIDatabase(protoRequest);

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                int totalSize = 0;
                int chunkCount = 0;

                while (chunks.hasNext()) {
                    SNIDataChunk chunk = chunks.next();
                    chunkCount++;
                    baos.write(chunk.getData().toByteArray());
                    totalSize = chunk.getTotalSize();

                    if (chunk.getIsLast()) {
                        log.info("Last SNI chunk received, total: {} bytes, chunks: {}", totalSize, chunkCount);
                    }
                }

                return baos.toByteArray();

            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() == Status.Code.UNAVAILABLE) {
                    log.error("Connection lost while downloading SNI database", e);
                    throw new ConnectionException("Connection lost: " + e);
                }
                throw e;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public SNIDataChunkResponse uploadDatabase(SnifferEntity sniffer, byte[] compressedData) {
        return sessionManager.executeWithSession(sniffer, session -> {
            try {
                int offset = 0;
                int chunkCount = 0;
                int totalSize = compressedData.length;

                while (offset < totalSize) {
                    int end = Math.min(offset + CHUNK_SIZE, totalSize);
                    offset = end;
                    chunkCount++;
                }

                return SNIDataChunkResponse.newBuilder()
                        .setSuccess(true)
                        .setMessage("Uploaded")
                        .setTotalChunks(chunkCount)
                        .build();

            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() == Status.Code.UNAVAILABLE) {
                    log.error("Connection lost while uploading SNI database", e);
                    throw new ConnectionException("Connection lost: " + e);
                }
                throw e;
            }
        });
    }

    public SNIEntry updateOrSaveEntry(SnifferEntity sniffer, SNIEntry entry) {
        return sessionManager.executeWithSession(sniffer, session -> {
            SNIEntry request = entry.toBuilder()
                    .setSessionKey(session.getSessionKey())
                    .build();

            try {
                return sessionManager.getStub(session)
                        .updateOrSaveSNIEntry(request);
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() == Status.Code.UNAVAILABLE) {
                    log.error("Connection lost for SNI entry update", e);
                    throw new ConnectionException("Connection lost: " + e);
                }
                throw e;
            }
        });
    }
}