export interface AuditLogDTO {
    id: string;
    userId: string;
    action: string;
    target: string;
    details: string;
    ipAddress: string;
    timestamp: number;
    userName: string;
}

export interface PageResponse<T> {
    content: T[];
    page: {
        size: number;
        number: number;
        totalElements: number;
        totalPages: number;
    };
}