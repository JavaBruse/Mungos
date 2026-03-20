package com.JavaBruse.core.sniffer.grpc.command;

import com.JavaBruse.core.exaption.ConnectionException;
import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.proto.*;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Component
public class JA4DatabaseCommand {

    private static final int CHUNK_SIZE = 32 * 1024;
    private final SessionManager sessionManager;

    public JA4DatabaseCommand(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    public byte[] downloadDatabase(SnifferEntity sniffer) {
        return sessionManager.executeWithSession(sniffer, session -> {
            Ja4DataChunkRequest protoRequest = Ja4DataChunkRequest.newBuilder()
                    .setSessionKey(session.getSessionKey())
                    .build();

            try {
                Iterator<Ja4DataChunk> chunks = sessionManager.getStub(session)
                        .downloadJA4Database(protoRequest);

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                int totalSize = 0;
                int chunkCount = 0;

                while (chunks.hasNext()) {
                    Ja4DataChunk chunk = chunks.next();
                    chunkCount++;
                    baos.write(chunk.getData().toByteArray());
                    totalSize = chunk.getTotalSize();

                    if (chunk.getIsLast()) {
                        log.info("Last JA4 chunk received, total: {} bytes, chunks: {}", totalSize, chunkCount);
                    }
                }

                return baos.toByteArray();

            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() == Status.Code.UNAVAILABLE) {
                    log.error("Connection lost while downloading JA4 database", e);
                    throw new ConnectionException("Connection lost: " + e);
                }
                throw e;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Ja4DataChunkResponse uploadDatabase(SnifferEntity sniffer, byte[] compressedData) {
        return sessionManager.executeWithSession(sniffer, session -> {
            try {
                final CountDownLatch latch = new CountDownLatch(1);
                final AtomicReference<Ja4DataChunkResponse> responseRef = new AtomicReference<>();
                final AtomicReference<Throwable> errorRef = new AtomicReference<>();

                var streamObserver = sessionManager.getAsyncStub(session)
                        .uploadJA4Database(new StreamObserver<Ja4DataChunkResponse>() {
                            @Override
                            public void onNext(Ja4DataChunkResponse response) {
                                responseRef.set(response);
                            }
                            @Override
                            public void onError(Throwable t) {
                                errorRef.set(t);
                                latch.countDown();
                            }
                            @Override
                            public void onCompleted() {
                                latch.countDown();
                            }
                        });

                int offset = 0;
                int chunkCount = 0;
                int totalSize = compressedData.length;

                while (offset < totalSize) {
                    int end = Math.min(offset + CHUNK_SIZE, totalSize);
                    boolean isLast = (end == totalSize);

                    Ja4DataChunk chunk = Ja4DataChunk.newBuilder()
                            .setSessionKey(session.getSessionKey())
                            .setData(com.google.protobuf.ByteString.copyFrom(compressedData, offset, end - offset))
                            .setIsLast(isLast)
                            .setTotalSize(totalSize)
                            .build();

                    streamObserver.onNext(chunk);
                    offset = end;
                    chunkCount++;
                }

                streamObserver.onCompleted();
                latch.await(30, TimeUnit.SECONDS);

                if (errorRef.get() != null) {
                    throw new RuntimeException(errorRef.get());
                }

                return responseRef.get() != null ? responseRef.get() :
                        Ja4DataChunkResponse.newBuilder().setSuccess(true).setTotalChunks(chunkCount).build();

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() == Status.Code.UNAVAILABLE) {
                    log.error("Connection lost while uploading JA4 database", e);
                    throw new ConnectionException("Connection lost: " + e);
                }
                throw e;
            }
        });
    }

    public JA4Entry updateOrSaveEntry(SnifferEntity sniffer, JA4Entry entry) {
        return sessionManager.executeWithSession(sniffer, session -> {
            JA4Entry request = entry.toBuilder()
                    .setSessionKey(session.getSessionKey())
                    .build();

            try {
                return sessionManager.getStub(session)
                        .updateOrSaveJa4Entry(request);
            } catch (StatusRuntimeException e) {
                if (e.getStatus().getCode() == Status.Code.UNAVAILABLE) {
                    log.error("Connection lost for JA4 entry update", e);
                    throw new ConnectionException("Connection lost: " + e);
                }
                throw e;
            }
        });
    }
}