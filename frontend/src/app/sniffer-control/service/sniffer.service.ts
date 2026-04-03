
import { Injectable, inject, signal } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpService } from '../../services/http.service';
import { SnifferRequestDTO } from './sniffer-request.DTO';
import { SnifferResponseDTO } from './sniffer-response.DTO';
import { ErrorMessageService } from '../../services/error-message.service';
import { SnifferSetting } from './sniffer-setting';
import { ConnectionInsight } from '../../handler-package.component/connection-insight.DTO';
import { UpdateInsightDTO } from '../../handler-package.component/update-insight.DTO';

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
    private readonly syncInProgressSignal = signal(false);
    readonly syncInProgress = this.syncInProgressSignal.asReadonly();

    getConnectionInsight(snifferId: string, packetId: string) {
        return this.http.get<ConnectionInsight>(`${this.apiUrl}/insight/${snifferId}/${packetId}`);
    }

    updateConnectionInsight(snifferId: string, packetId: string, ja4EntryId?: string, sniEntryId?: string) {
        const body: UpdateInsightDTO = { ja4EntryId, sniEntryId };
        return this.http.post<void>(`${this.apiUrl}/insight/${snifferId}/${packetId}`, body);
    }

    loadAll() {
        this.http.get<SnifferResponseDTO[]>(`${this.apiUrl}/all`).subscribe({
            next: (sniffers) => {
                const sorted = sniffers.sort((a, b) => a.id.localeCompare(b.id));
                this.sniffersSignal.set(sorted);
            },
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


    // Синхронизация JA4 баз данных
    syncJA4Databases() {
        this.syncInProgressSignal.set(true);
        this.http.post<void>(`${this.apiUrl}/ja4/sync`, {}).subscribe({
            next: () => {
                this.errorMessageService.showSuccess("Синхронизация JA4 баз завершена");
                this.syncInProgressSignal.set(false);
            },
            error: () => {
                this.errorMessageService.showError("Ошибка синхронизации JA4 баз");
                this.syncInProgressSignal.set(false);
            },
        });
    }

    // Синхронизация SNI баз данных
    syncSNIDatabases() {
        this.syncInProgressSignal.set(true);
        this.http.post<void>(`${this.apiUrl}/sni/sync`, {}).subscribe({
            next: () => {
                this.errorMessageService.showSuccess("Синхронизация SNI баз завершена");
                this.syncInProgressSignal.set(false);
            },
            error: () => {
                this.errorMessageService.showError("Ошибка синхронизации SNI баз");
                this.syncInProgressSignal.set(false);
            },
        });
    }

    // Обновление хэшей всех снифферов
    updateAllHashes() {
        this.syncInProgressSignal.set(true);
        this.http.post<void>(`${this.apiUrl}/hashes/update-all`, {}).subscribe({
            next: () => {
                this.errorMessageService.showSuccess("Хэши всех снифферов обновлены");
                this.loadAll();
                this.syncInProgressSignal.set(false);
            },
            error: () => {
                this.errorMessageService.showError("Ошибка обновления хэшей");
                this.syncInProgressSignal.set(false);
            },
        });
    }

    downloadJA4Database(snifferId: string) {
        this.http.getBlob(`${this.apiUrl}/export/ja4?snifferId=${snifferId}`).subscribe({
            next: (blob) => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `ja4_database.xlsx`;
                a.click();
                window.URL.revokeObjectURL(url);
                this.errorMessageService.showSuccess("JA4 база скачана");
            },
            error: () => {
                this.errorMessageService.showError("Ошибка скачивания JA4 базы");
            }
        });
    }

    downloadSNIDatabase(snifferId: string) {
        this.http.getBlob(`${this.apiUrl}/export/sni?snifferId=${snifferId}`).subscribe({
            next: (blob) => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `sni_database.xlsx`;
                a.click();
                window.URL.revokeObjectURL(url);
                this.errorMessageService.showSuccess("SNI база скачана");
            },
            error: () => {
                this.errorMessageService.showError("Ошибка скачивания SNI базы");
            }
        });
    }

    uploadJA4Database(snifferId: string, file: File) {
        const formData = new FormData();
        formData.append('snifferId', snifferId);
        formData.append('file', file);

        this.http.post<void>(`${this.apiUrl}/upload/ja4`, formData).subscribe({
            next: () => {
                this.errorMessageService.showSuccess("JA4 база загружена");
            },
            error: () => {
                this.errorMessageService.showError("Ошибка загрузки JA4 базы");
            }
        });
    }

    uploadSNIDatabase(snifferId: string, file: File) {
        const formData = new FormData();
        formData.append('snifferId', snifferId);
        formData.append('file', file);

        this.http.post<void>(`${this.apiUrl}/upload/sni`, formData).subscribe({
            next: () => {
                this.errorMessageService.showSuccess("SNI база загружена");
            },
            error: () => {
                this.errorMessageService.showError("Ошибка загрузки SNI базы");
            }
        });
    }

    canSyncJA4(): boolean {
        const sniffers = this.sniffersSignal();
        if (sniffers.length <= 1) return false;

        const hashes = sniffers.map(s => s.Ja4Hash);
        const firstHash = hashes[0];
        return !hashes.every(hash => hash === firstHash);
    }

    canSyncSNI(): boolean {
        const sniffers = this.sniffersSignal();
        if (sniffers.length <= 1) return false;

        const hashes = sniffers.map(s => s.SNIHash);
        const firstHash = hashes[0];
        return !hashes.every(hash => hash === firstHash);
    }

}