package com.JavaBruse.core.exaption;

public class ConnectionException extends RuntimeException {
    public ConnectionException(String msg) {
        super(msg);
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
