export interface ConnectionInsight {
    localIp: string;
    localPorts: number[];
    remoteIp: string;
    remotePort: number;
    totalPackets: number;
    totalBytes: number;
    firstPacketTime: number;
    lastPacketTime: number;
    synCount: number;
    finCount: number;
    rstCount: number;
    identifiedPackets: number;
    ja4Candidates: JA4Candidate[];
    sniCandidates: SNICandidate[];
}

export interface JA4Candidate {
    id: string;
    fingerprint: string;
    application: string;
    device: string;
    os: string;
    count: number;
    confidence: number;
    hop: number;
}

export interface SNICandidate {
    id: string;
    sni: string;
    service: string;
    count: number;
    confidence: number;
    hop: number;
}