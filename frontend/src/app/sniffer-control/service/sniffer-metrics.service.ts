import { Injectable, inject, signal, DestroyRef } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpService } from '../../services/http.service';
import { timer, switchMap, catchError, of, map } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

export interface SnifferMetric {
    snifferId: string;
    value: number;
}

@Injectable({
    providedIn: 'root',
})
export class SnifferMetricsService {
    private http = inject(HttpService);
    private destroyRef = inject(DestroyRef);
    private apiUrl = environment.apiUrl + 'api/proxy/prometheus';
    public metrics = signal<SnifferMetric[]>([]);

    constructor() {
        timer(0, 60000)
            .pipe(
                takeUntilDestroyed(this.destroyRef),
                switchMap(() => this.fetchMetrics()),
                catchError((err) => {
                    console.error('Ошибка загрузки метрик:', err);
                    return of(null);
                })
            )
            .subscribe((data) => {
                if (data) {
                    this.metrics.set(data);
                }
            });
    }

    private fetchMetrics() {
        const queryUrl = `${this.apiUrl}/api/v1/query?query=sniffer_unknown_packets`;
        return this.http.get<any>(queryUrl).pipe(
            map((response) => {
                const result: SnifferMetric[] = [];

                if (response?.data?.result) {
                    response.data.result.forEach((item: any) => {
                        result.push({
                            snifferId: item.metric.sniffer_id || item.metric.id || 'unknown',
                            value: parseFloat(item.value[1]) || 0
                        });
                    });
                }
                return result;
            })
        );
    }

    public getTotalUnknown(): number {
        return this.metrics().reduce((sum, m) => sum + m.value, 0);
    }

    public getValue(snifferId: string): number {
        return this.metrics().find(m => m.snifferId === snifferId)?.value ?? 0;
    }
}