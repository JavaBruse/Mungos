
import { Injectable, inject, signal } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpService } from '../../services/http.service';
import { SnifferRequestDTO } from './sniffer-request.DTO';
import { SnifferResponseDTO } from './sniffer-response.DTO';
import { ErrorMessageService } from '../../services/error-message.service';
import { SnifferSetting } from './sniffer-setting';

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
    private readonly visibleSettingSignal = signal(false)
    private errorMessageService = inject(ErrorMessageService)
    readonly sniffers = this.sniffersSignal.asReadonly();
    readonly visibleAdd = this.visibleAddSnifferSignal.asReadonly();
    readonly visibleSetting = this.visibleSettingSignal.asReadonly();
    snifferSetting = signal<SnifferSetting | null>(null);


    loadAll() {
        this.http.get<SnifferResponseDTO[]>(`${this.apiUrl}/all`).subscribe({
            next: (sniffers) => this.sniffersSignal.set(sniffers),
            error: () => { },
        });
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
            next: () => {
                this.loadAll();
                this.errorMessageService.showSuccess("Ответ получен");
            },
            error: () => {
            },
        });
    }

    getSetting(id: string) {
        this.http.get<SnifferSetting>(`${this.apiUrl}/setting/${id}`).subscribe({
            next: (setting) => this.snifferSetting.set(setting),
            error: () => this.snifferSetting.set(null)
        });
    }
    saveSetting(snifferSetting: SnifferSetting) {
        this.http.post<void>(`${this.apiUrl}/setting`, snifferSetting).subscribe({
            next: () => {
                this.loadAll();
                this.errorMessageService.showSuccess("Настройки сохранены");
            },
            error: () => {
                this.errorMessageService.showError("Ошибка сохранения настроек");
            },
        });
    }


    setVisibleAdd(value: boolean) {
        this.visibleAddSnifferSignal.set(value);
    }

    clear() {
        this.sniffersSignal.set([]);
        this.visibleAddSnifferSignal.set(false);
        this.visibleSettingSignal.set(false);
    }
}