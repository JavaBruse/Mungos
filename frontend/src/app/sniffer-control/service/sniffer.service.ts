
import { Injectable, inject, signal } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpService } from '../../services/http.service';
import { SnifferRequestDTO } from './sniffer-request.DTO';
import { SnifferResponseDTO } from './sniffer-response.DTO';
import { SnifferWebSocketService } from './sniffer-websocket.service';

@Injectable({
    providedIn: 'root',
})
export class SnifferService {
    private http = inject(HttpService);
    private url = environment.apiUrl;
    private apiUrl = this.url + 'api/v1/sniffer';
    dialogTitle: string | null = null;
    dialogDisk: string | null = null;
    private readonly sniffersSignal = signal<SnifferResponseDTO[]>([]);
    private readonly visibleAddSnifferSignal = signal(false);
    private wsService = inject(SnifferWebSocketService);

    readonly sniffers = this.sniffersSignal.asReadonly();
    readonly visibleAdd = this.visibleAddSnifferSignal.asReadonly();

    loadAll() {
        this.http.get<SnifferResponseDTO[]>(`${this.apiUrl}/all`).subscribe({
            next: (sniffers) => this.sniffersSignal.set(sniffers),
            error: () => { },
        });
    }

    requestTrafficStream(snifferId: string, period: string) {
        this.wsService.requestTraffic(snifferId, period);
    }

    add(snifferData: SnifferRequestDTO) {
        this.http.post<any>(`${this.apiUrl}/create`, snifferData).subscribe({
            next: (response) => { this.loadAll(); },
            error: () => { },
        });
    }

    delete(id: string) {
        this.http.delete<void>(`${this.apiUrl}/delete/${id}`).subscribe({
            next: () => { this.loadAll(); },
            error: () => { },
        });
    }

    ping(id: string) {
        this.http.get<void>(`${this.apiUrl}/ping/${id}`).subscribe({
            next: () => { this.loadAll(); },
            error: () => { },
        });
    }

    setVisibleAdd(value: boolean) {
        this.visibleAddSnifferSignal.set(value);
    }

    clear() {
        this.sniffersSignal.set([]);
        this.visibleAddSnifferSignal.set(false);
    }
}