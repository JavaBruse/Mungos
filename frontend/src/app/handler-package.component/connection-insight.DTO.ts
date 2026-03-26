// models/connection-insight.ts
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
    identificData: IdentificData[];
}

export interface IdentificData {
    uniqueJa4Raw: string[];
    uniqueJa4Application: string[];
    uniqueJa4Device: string[];
    uniqueJa4Os: string[];
    uniqueSni: string[];
    uniqueSniService: string[];
    uniqueJa4EntryId: string[];
    uniqueSniEntryId: string[];
    relatedAddressJa4: RelatedAddress[];
    relatedAddressSni: RelatedAddress[];
}

export interface RelatedAddress {
    remoteIp: string;
    remotePort: number;
    count: number;
}