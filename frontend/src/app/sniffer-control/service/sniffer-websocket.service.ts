import { Injectable } from '@angular/core';
import { Client, Message } from '@stomp/stompjs';
import { environment } from '../../../environments/environment';
import { Subject, Observable } from 'rxjs';

export interface TrafficPacket {
    packetId: string;
    timestamp: number;
    protocol: string;
    srcPort: number;
    dstPort: number;
    srcIp: string;
    dstIp: string;
    length: number;
    hasPayload: boolean;
    headers?: Record<string, string>;
    method?: string;
    uri?: string;
    status?: number;
    dnsQuery?: string;
    dnsAnswer?: string;
    loadingPayload?: boolean;
    payload?: string;
}

export interface TrafficRequest {
    snifferId: string;
    protocols?: string[];
    ports?: number[];
    ips?: string[];
    startTime?: number;
    endTime?: number;
    textSearch?: string;
    limit: number;
    offset: number;
}

@Injectable({
    providedIn: 'root'
})
export class SnifferWebSocketService {
    private stompClient: Client | null = null;
    private connected = false;
    private isActive = false;
    private packetSubject = new Subject<TrafficPacket>();
    private completeSubject = new Subject<number>();
    private errorSubject = new Subject<string>();
    private payloadSubjects = new Map<string, Subject<string>>();

    private offsets = new Map<string, number>();

    get packets$(): Observable<TrafficPacket> {
        return this.packetSubject.asObservable();
    }

    get complete$(): Observable<number> {
        return this.completeSubject.asObservable();
    }

    get error$(): Observable<string> {
        return this.errorSubject.asObservable();
    }

    getOffset(snifferId: string): number {
        return this.offsets.get(snifferId) || 0;
    }

    setOffset(snifferId: string, offset: number) {
        this.offsets.set(snifferId, offset);
    }

    clearOffset(snifferId: string) {
        this.offsets.delete(snifferId);
    }

    connect() {
        if (this.isActive) {
            console.log('Already active, reconnecting...');
            this.disconnect();
        }
        this.packetSubject = new Subject<TrafficPacket>();
        this.completeSubject = new Subject<number>();
        this.errorSubject = new Subject<string>();
        this.isActive = true;
        this.initializeWebSocket();
    }

    isConnected(): boolean {
        return this.connected;
    }

    private initializeWebSocket() {
        const token = localStorage.getItem('Authorization');
        this.stompClient = new Client({
            brokerURL: environment.apiUrl.replace('http', 'ws') + 'api/v1/ws-sniffer',
            connectHeaders: {
                Authorization: token || ''
            },
            reconnectDelay: 5000
        });

        this.stompClient.onConnect = () => {
            console.log('WebSocket connected');
            this.connected = true;
        };

        this.stompClient.onDisconnect = () => {
            console.log('WebSocket disconnected');
            this.connected = false;
        };

        this.stompClient.activate();
    }

    subscribeToTraffic(snifferId: string) {
        if (!this.stompClient || !this.connected) {
            console.error('WebSocket not connected');
            return;
        }

        // Подписка на пакеты
        this.stompClient.subscribe(`/api/v1/topic/traffic/${snifferId}/packet`, (message: Message) => {
            const packet = JSON.parse(message.body);
            this.packetSubject.next(packet);
        });

        // Подписка на завершение
        this.stompClient.subscribe(`/api/v1/topic/traffic/${snifferId}/complete`, (message: Message) => {
            const data = JSON.parse(message.body);
            this.completeSubject.next(data.totalPackets);
        });

        // Подписка на ошибки
        this.stompClient.subscribe(`/api/v1/topic/traffic/${snifferId}/error`, (message: Message) => {
            const data = JSON.parse(message.body);
            this.errorSubject.next(data.error);
        });
    }

    getPayload$(packetId: string): Observable<string> {
        if (!this.payloadSubjects.has(packetId)) {
            this.payloadSubjects.set(packetId, new Subject<string>());

            // Добавить проверку
            if (this.stompClient) {
                this.stompClient.subscribe(`/api/v1/topic/payload/${packetId}`, (message: Message) => {
                    const payload = message.body;
                    this.payloadSubjects.get(packetId)?.next(payload);
                    this.payloadSubjects.get(packetId)?.complete();
                });
            } else {
                console.error('STOMP client not initialized');
                this.payloadSubjects.get(packetId)?.error('STOMP client not initialized');
            }
        }

        return this.payloadSubjects.get(packetId)!.asObservable();
    }

    requestPayload(snifferId: string, packetId: string) {
        if (!this.stompClient) {
            console.error('STOMP client not initialized');
            return;
        }

        this.stompClient.publish({
            destination: '/api/v1/app/traffic.payload',
            body: JSON.stringify({
                snifferId: snifferId,
                packetId: packetId
            })
        });
    }

    requestTraffic(request: TrafficRequest) {
        if (!this.stompClient || !this.connected) {
            console.error('WebSocket not connected');
            return;
        }
        this.stompClient.publish({
            destination: '/api/v1/app/traffic.request',
            body: JSON.stringify(request)
        });
    }

    disconnect() {
        this.isActive = false;
        this.connected = false;

        if (this.stompClient) {
            this.stompClient.deactivate();
            this.stompClient = null;
        }
    }
}