package com.JavaBruse.core.sniffer.grpc.client;

import lombok.Value;

@Value
public class ConnectionResult {
    boolean success;
    boolean busy;
    String sessionKey;
    String certificate;
    String errorMessage;

    private ConnectionResult(boolean success, boolean busy, String sessionKey, String certificate, String errorMessage) {
        this.success = success;
        this.busy = busy;
        this.sessionKey = sessionKey;
        this.certificate = certificate;
        this.errorMessage = errorMessage;
    }

    public static ConnectionResult success(String sessionKey, String certificate) {
        return new ConnectionResult(true, false, sessionKey, certificate, null);
    }

    public static ConnectionResult failure(String errorMessage) {
        return new ConnectionResult(false, false, null, null, errorMessage);
    }

    public static ConnectionResult busy(String errorMessage) {
        return new ConnectionResult(false, true, null, null, errorMessage);
    }
}