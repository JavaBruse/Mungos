import { Injectable, inject, signal } from '@angular/core';
import { environment } from '../../environments/environment';
import { HttpService } from '../services/http.service';
import { HttpParams } from '@angular/common/http';

export interface MetricData {
    time: Date;
    value: number;
}

@Injectable({
    providedIn: 'root'
})
export class MetricService {
    private http = inject(HttpService);
    private apiUrl = environment.apiUrl + 'api/proxy/prometheus';

    private readonly metricsSignal = signal<Map<string, MetricData[]>>(new Map());
    private readonly loadingSignal = signal<boolean>(false);
    private readonly errorSignal = signal<string | null>(null);

    readonly metrics = this.metricsSignal.asReadonly();
    readonly loading = this.loadingSignal.asReadonly();
    readonly error = this.errorSignal.asReadonly();

    queryRange(query: string, start: Date, end: Date, step: string) {
        this.loadingSignal.set(true);
        this.errorSignal.set(null);

        const params = new HttpParams()
            .set('query', query)
            .set('start', start.toISOString())
            .set('end', end.toISOString())
            .set('step', step);

        this.http.get<any>(`${this.apiUrl}/api/v1/query_range`, params).subscribe({
            next: (response) => {
                const newMetrics = new Map(this.metricsSignal()); // сохраняем старые

                if (response.data?.result) {
                    response.data.result.forEach((result: any) => {
                        const metricLabels = JSON.stringify(result.metric);
                        const key = `${query}_${metricLabels}`;

                        const values = result.values.map((v: any[]) => ({
                            time: new Date(v[0] * 1000),
                            value: parseFloat(v[1])
                        }));
                        newMetrics.set(key, values);
                    });
                }

                this.metricsSignal.set(newMetrics);
                this.loadingSignal.set(false);
            },
            error: (err) => {
                this.errorSignal.set(err.message);
                this.loadingSignal.set(false);
            }
        });
    }

    clear() {
        this.metricsSignal.set(new Map());
        this.errorSignal.set(null);
        this.loadingSignal.set(false);
    }
}