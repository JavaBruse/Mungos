import { Injectable, signal } from '@angular/core';

@Injectable({
    providedIn: 'root',
})
export class LoadingService {
    public loadingSignal = signal(false);
    private requestCount = 0;

    setLoading(isLoading: boolean) {
        if (isLoading) {
            this.requestCount++;
        } else {
            this.requestCount = Math.max(0, this.requestCount - 1);
        }
        this.loadingSignal.set(this.requestCount > 0);
    }
}
