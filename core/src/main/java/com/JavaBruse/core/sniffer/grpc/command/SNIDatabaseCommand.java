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
                final CountDownLatch latch = new CountDownLatch(1);
                final AtomicReference<SNIDataChunkResponse> responseRef = new AtomicReference<>();
                final AtomicReference<Throwable> errorRef = new AtomicReference<>();

                var streamObserver = sessionManager.getAsyncStub(session)
                        .uploadSNIDatabase(new StreamObserver<SNIDataChunkResponse>() {
                            @Override
                            public void onNext(SNIDataChunkResponse response) {
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

                    SNIDataChunk chunk = SNIDataChunk.newBuilder()
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
                        SNIDataChunkResponse.newBuilder().setSuccess(true).setTotalChunks(chunkCount).build();

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
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