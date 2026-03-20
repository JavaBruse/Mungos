package com.JavaBruse.core.sniffer.grpc;

import com.google.protobuf.Message;
import lombok.experimental.UtilityClass;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

@UtilityClass
public class ProtoCompressor {

    public static byte[] compressProto(Message message) throws IOException {
        byte[] data = message.toByteArray();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            gzip.write(data);
        }

        return baos.toByteArray();
    }

    public static <T extends Message> T decompressProto(byte[] compressedData, Class<T> clazz) throws IOException {
        try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(compressedData))) {
            byte[] uncompressed = gzip.readAllBytes();

            try {
                Method parseMethod = clazz.getMethod("parseFrom", byte[].class);
                return clazz.cast(parseMethod.invoke(null, (Object) uncompressed));
            } catch (Exception e) {
                throw new IOException("Failed to parse protobuf message", e);
            }
        }
    }
}