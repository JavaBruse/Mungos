import { Injectable, signal } from '@angular/core';
export type MessageType = 'success' | 'error' | 'warning' | 'info';


export interface Message {
    text: string;
    type: MessageType;
}
@Injectable({
    providedIn: 'root'
})
export class ErrorMessageService {
    private messageSignal = signal<Message | null>(null);

    get message$() {
        return this.messageSignal;
    }

    showSuccess(message: string) {
        this.message$.set({ text: message, type: 'success' });
    }

    showError(message: string) {
        this.message$.set({ text: message, type: 'error' });
    }

    showWarning(message: string) {
        this.message$.set({ text: message, type: 'warning' });
    }

    showInfo(message: string) {
        this.message$.set({ text: message, type: 'info' });
    }

    clearMessage() {
        this.message$.set(null);
    }
}
