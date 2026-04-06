import { Injectable, inject, signal, DestroyRef } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpService } from '../../services/http.service';
import { timer, switchMap, catchError, of, map, forkJoin } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

export interface SnifferMetric {
    snifferId: string;
    unknown: number;
    known: number;
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
                switchMap(() => this.fetchAllMetrics()),
                catchError((err) => {
                    console.error('Ошибка загрузки метрик:', err);
                    return of([]);
                })
            )
            .subscribe((data) => {
                if (data) {
                    this.metrics.set(data);
                }
            });
    }

    private fetchAllMetrics() {
        return forkJoin({
            unknown: this.fetchUnknownMetrics(),
            known: this.fetchKnownMetrics()
        }).pipe(
            map(({ unknown, known }) => {
                const resultMap = new Map<string, SnifferMetric>();

                unknown.forEach(item => {
                    resultMap.set(item.snifferId, {
                        snifferId: item.snifferId,
                        unknown: item.value,
                        known: 0
                    });
                });

                known.forEach(item => {
                    const existing = resultMap.get(item.snifferId);
                    if (existing) {
                        existing.known = item.value;
                    } else {
                        resultMap.set(item.snifferId, {
                            snifferId: item.snifferId,
                            unknown: 0,
                            known: item.value
                        });
                    }
                });

                return Array.from(resultMap.values());
            })
        );
    }

    private fetchUnknownMetrics() {
        const queryUrl = `${this.apiUrl}/api/v1/query?query=sniffer_unknown_packets`;
        return this.http.get<any>(queryUrl).pipe(
            map((response) => {
                const result: { snifferId: string, value: number }[] = [];
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

    private fetchKnownMetrics() {
        const queryUrl = `${this.apiUrl}/api/v1/query?query=sniffer_known_packets`;
        return this.http.get<any>(queryUrl).pipe(
            map((response) => {
                const result: { snifferId: string, value: number }[] = [];
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
        return this.metrics().reduce((sum, m) => sum + m.unknown, 0);
    }

    public getTotalKnown(): number {
        return this.metrics().reduce((sum, m) => sum + m.known, 0);
    }

    public getUnknown(snifferId: string): number {
        return this.metrics().find(m => m.snifferId === snifferId)?.unknown ?? 0;
    }

    public getKnown(snifferId: string): number {
        return this.metrics().find(m => m.snifferId === snifferId)?.known ?? 0;
    }
}