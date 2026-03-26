import { Component, Input, Output, EventEmitter, signal, inject, OnInit, OnDestroy, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SnifferService } from '../sniffer-control/service/sniffer.service';
import { ConnectionInsight } from './connection-insight.DTO';
import { Subscription } from 'rxjs';
import { MatTabsModule } from '@angular/material/tabs';
import { ErrorMessageService } from '../services/error-message.service';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';

@Component({
  selector: 'app-handler-package',
  standalone: true,
  imports: [CommonModule, MatTabsModule, MatSelectModule,
    MatButtonModule,
    MatFormFieldModule],
  templateUrl: './handler-package.component.html',
  styleUrl: './handler-package.component.scss',
})
export class HandlerPackageComponent implements OnInit, OnDestroy {
  private snifferService = inject(SnifferService);
  private subscription: Subscription | null = null;
  private loaded = false; // 👈 флаг загрузки
  messages = inject(ErrorMessageService)
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

  getPortRange(ports: number[]): string {
    if (!ports.length) return '';
    const min = Math.min(...ports);
    const max = Math.max(...ports);
    return `${min}-${max}`;
  }

  ngOnDestroy() {
    if (this.subscription) {
      this.subscription.unsubscribe();
    }
  }

  updateInsight(ja4EntryId?: string, sniEntryId?: string) {
    this.snifferService.updateConnectionInsight(this.snifferId, this.packetId, ja4EntryId, sniEntryId).subscribe({
      next: () => {
        this.messages.showSuccess('Данные обновлнены')
        this.close.emit();
      },
      error: () => {
        this.messages.showError('Ошибка сохранения');
      }
    });
  }

  selectedJa4Id = '';
  selectedSniId = '';

  allJa4EntryIds = computed(() => {
    const ids = new Set<string>();
    this.insight()?.identificData?.forEach(data => {
      console.log('JA4 IDs from data:', data.uniqueJa4EntryId); // 👈 лог
      data.uniqueJa4EntryId.forEach(id => ids.add(id));
    });
    console.log('All JA4 IDs:', Array.from(ids)); // 👈 лог
    return Array.from(ids);
  });

  allSniEntryIds = computed(() => {
    const ids = new Set<string>();
    this.insight()?.identificData?.forEach(data => {
      data.uniqueSniEntryId.forEach(id => ids.add(id));
    });
    return Array.from(ids);
  });

  applyInsight() {
    if (!this.selectedJa4Id && !this.selectedSniId) return;
    this.updateInsight(this.selectedJa4Id, this.selectedSniId);
  }
}