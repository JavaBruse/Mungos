import { Component, Input, Output, EventEmitter, signal, inject, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SnifferService } from '../sniffer-control/service/sniffer.service';
import { ConnectionInsight } from './connection-insight.DTO';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-handler-package',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './handler-package.component.html',
  styleUrl: './handler-package.component.scss',
})
export class HandlerPackageComponent implements OnInit, OnDestroy {
  private snifferService = inject(SnifferService);
  private subscription: Subscription | null = null;
  private loaded = false; // 👈 флаг загрузки

  @Input() snifferId = '';
  @Input() packetId = '';

  @Output() close = new EventEmitter<void>();

  insight = signal<ConnectionInsight | null>(null);
  error = signal<string | null>(null);

  ngOnInit() {
    this.loadInsight();
  }

  private loadInsight() {
    if (!this.snifferId || !this.packetId) return;
    if (this.loaded) return; // 👈 если уже загрузили, выходим

    this.error.set(null);

    if (this.subscription) {
      this.subscription.unsubscribe();
    }

    this.subscription = this.snifferService.getConnectionInsight(this.snifferId, this.packetId).subscribe({
      next: (data) => {
        this.insight.set(data);
        this.loaded = true; // 👈 помечаем как загруженное
      },
      error: () => {
        this.error.set('Ошибка загрузки данных');
        this.loaded = true; // 👈 даже при ошибке помечаем
      }
    });
  }

  onBackdropClick(event: MouseEvent) {
    if (event.target === event.currentTarget) {
      this.close.emit();
    }
  }

  formatTimestamp(timestamp: number): string {
    return new Date(timestamp / 1000000).toLocaleString();
  }

  ngOnDestroy() {
    if (this.subscription) {
      this.subscription.unsubscribe();
    }
  }
}