export interface SnifferResponseDTO {
    id: string;
    name: string;
    location: string;
    host: string;
    port: number;
    lastSeen: number;
    connected: boolean;
    SNIHash: string;
    Ja4Hash: string;
}