import { Injectable } from '@angular/core';
import { Client, Message } from '@stomp/stompjs';
import { environment } from '../../../environments/environment';

@Injectable({
    providedIn: 'root'
})
export class SnifferWebSocketService {
    private stompClient: Client | null = null;
    private connected = false;
    private isActive = false;

    connect() {
        if (this.isActive) return;

        this.isActive = true;
        this.initializeWebSocket();
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

    subscribeToTraffic(snifferId: string, callback: (data: any) => void) {
        if (!this.stompClient || !this.connected) {
            console.error('WebSocket not connected');
            return;
        }

        return this.stompClient.subscribe(`/api/v1/topic/traffic/${snifferId}`, (message: Message) => {
            const data = JSON.parse(message.body);
            callback(data);
        });
    }

    requestTraffic(snifferId: string, period: string) {
        if (!this.stompClient || !this.connected) {
            console.error('WebSocket not connected');
            return;
        }

        this.stompClient.publish({
            destination: '/api/v1/app/traffic.request',
            body: JSON.stringify({
                snifferId: snifferId,
                period: period
            })
        });
    }

    // вызывать при выходе из компонента
    disconnect() {
        this.isActive = false;
        if (this.stompClient) {
            this.stompClient.deactivate();
            this.stompClient = null;
            this.connected = false;
        }
    }
}