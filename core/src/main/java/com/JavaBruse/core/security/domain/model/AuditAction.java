package com.JavaBruse.core.security.domain.model;

public enum AuditAction {
    LOGIN_SUCCESS("LOGIN_SUCCESS"),
    LOGIN_FAILED("LOGIN_FAILED"),
    ADD_SNIFFER("ADD_SNIFFER"),
    DELETE_SNIFFER("DELETE_SNIFFER"),
    UPDATE_SNIFFER_SETTINGS("UPDATE_SNIFFER_SETTINGS"),
    SYNC_JA4("SYNC_JA4"),
    SYNC_SNI("SYNC_SNI"),
    UPDATE_INSIGHT("UPDATE_INSIGHT"),
    CREATE_USER("CREATE_USER"),
    DELETE_USER("DELETE_USER"),
    UPDATE_USER_ROLE("UPDATE_USER");

    private final String value;

    AuditAction(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}