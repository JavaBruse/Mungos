import { Injectable, inject, signal } from '@angular/core';
import { environment } from '../../environments/environment';
import { HttpService } from '../services/http.service';
import { AuditLogDTO, PageResponse } from './audit-log.DTO';
import { HttpParams } from '@angular/common/http';

@Injectable({
    providedIn: 'root',
})
export class AuditLogService {
    private http = inject(HttpService);
    private url = environment.apiUrl;
    private apiUrl = this.url + 'api/v1/audit';

    private readonly logsSignal = signal<AuditLogDTO[]>([]);
    private readonly totalElementsSignal = signal<number>(0);
    private readonly totalPagesSignal = signal<number>(0);
    private readonly currentPageSignal = signal<number>(0);
    private readonly pageSizeSignal = signal<number>(25);
    private readonly loadingSignal = signal<boolean>(false);
    private readonly searchSignal = signal<string>('');

    readonly logs = this.logsSignal.asReadonly();
    readonly totalElements = this.totalElementsSignal.asReadonly();
    readonly totalPages = this.totalPagesSignal.asReadonly();
    readonly currentPage = this.currentPageSignal.asReadonly();
    readonly pageSize = this.pageSizeSignal.asReadonly();
    readonly loading = this.loadingSignal.asReadonly();
    readonly searchTerm = this.searchSignal.asReadonly();



    loadPage(page: number = 0, size: number = 25, searchString: string = this.searchSignal()) {
        this.loadingSignal.set(true);
        this.searchSignal.set(searchString);
        const params = new HttpParams()
            .set('page', page.toString())
            .set('size', size.toString())
            .set('sort', 'timestamp,desc')
            .set('userName', searchString);



        this.http.get<PageResponse<AuditLogDTO>>(`${this.apiUrl}/all`, params).subscribe({
            next: (response) => {
                this.logsSignal.set(response.content);
                this.totalElementsSignal.set(response.page.totalElements);
                this.totalPagesSignal.set(response.page.totalPages);
                this.currentPageSignal.set(response.page.number);
                this.pageSizeSignal.set(response.page.size);
                this.loadingSignal.set(false);
            },
            error: (err) => {
                console.error(err);
                this.logsSignal.set([]);
                this.loadingSignal.set(false);
            }
        });
    }

    reload() {
        this.loadPage(this.currentPageSignal(), this.pageSizeSignal());
    }

    setPageSize(size: number) {
        this.loadPage(0, size);
    }

    clear() {
        this.logsSignal.set([]);
        this.totalElementsSignal.set(0);
        this.totalPagesSignal.set(0);
        this.currentPageSignal.set(0);
        this.loadingSignal.set(false);
    }
}