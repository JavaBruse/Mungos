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
import { MatTooltipModule } from '@angular/material/tooltip';
import { JA4Candidate, SNICandidate } from './connection-insight.DTO';
import { MatRadioModule } from '@angular/material/radio';

@Component({
  selector: 'app-handler-package',
  standalone: true,
  imports: [CommonModule, MatTabsModule, MatSelectModule,
    MatButtonModule,
    MatFormFieldModule,
    MatTooltipModule, MatRadioModule
  ],
  templateUrl: './handler-package.component.html',
  styleUrl: './handler-package.component.scss',
})
export class HandlerPackageComponent implements OnInit, OnDestroy {
  private snifferService = inject(SnifferService);
  private subscription: Subscription | null = null;
  private loaded = false;
  messages = inject(ErrorMessageService)
  @Input() snifferId = '';
  @Input() packetId = '';
  @Output() close = new EventEmitter<void>();
  selectedJa4Id = '';
  selectedSniId = '';
  selectJA4(id: string) {
    this.selectedJa4Id = id;
  }

  selectSNI(id: string) {
    this.selectedSniId = id;
  }

  insight = signal<ConnectionInsight | null>(null);
  error = signal<string | null>(null);

  ngOnInit() {

    this.loadInsight();
  }

  private loadInsight() {
    if (!this.snifferId || !this.packetId) return;
    if (this.loaded) return;

    this.error.set(null);

    if (this.subscription) {
      this.subscription.unsubscribe();
    }

    this.subscription = this.snifferService.getConnectionInsight(this.snifferId, this.packetId).subscribe({
      next: (data) => {
        this.insight.set(data);

        if (data.ja4Candidates?.length && !this.selectedJa4Id) {
          this.selectedJa4Id = data.ja4Candidates[0].id;
        }
        if (data.sniCandidates?.length && !this.selectedSniId) {
          this.selectedSniId = data.sniCandidates[0].id;
        }

        this.loaded = true;
      },
      error: () => {
        this.error.set('Ошибка загрузки данных');
        this.loaded = true;
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

  allJa4Candidates = computed(() => {
    return this.insight()?.ja4Candidates || [];
  });

  allSniCandidates = computed(() => {
    return this.insight()?.sniCandidates || [];
  });

  applyInsight() {
    console.log('applyInsight called', this.selectedJa4Id, this.selectedSniId);
    if (!this.selectedJa4Id && !this.selectedSniId) return;
    this.updateInsight(this.selectedJa4Id, this.selectedSniId);
  }

  trackByJA4(index: number, item: JA4Candidate): string {
    return item.id || item.fingerprint || `ja4-${index}`;
  }

  trackBySNI(index: number, item: SNICandidate): string {
    return item.id || item.sni || `sni-${index}`;
  }


  sortedJa4Candidates = computed(() => {
    const candidates = this.insight()?.ja4Candidates || [];
    return [...candidates].sort((a, b) => {
      if (a.hop !== b.hop) {
        return a.hop - b.hop;
      }
      if (a.count !== b.count) {
        return (b.count || 0) - (a.count || 0);
      }
      return (b.confidence || 0) - (a.confidence || 0);
    });
  });

  sortedSniCandidates = computed(() => {
    const candidates = this.insight()?.sniCandidates || [];
    return [...candidates].sort((a, b) => {
      if (a.hop !== b.hop) {
        return a.hop - b.hop;
      }
      if (a.count !== b.count) {
        return (b.count || 0) - (a.count || 0);
      }
      return (b.confidence || 0) - (a.confidence || 0);
    });
  });

  getSubnet24(ip: string | undefined): string {
    if (!ip) return '';
    const parts = ip.split('.');
    if (parts.length >= 3) {
      return parts[0] + '.' + parts[1] + '.' + parts[2] + '.*';
    }
    return '';
  }

  getSubnet16(ip: string | undefined): string {
    if (!ip) return '';
    const parts = ip.split('.');
    if (parts.length >= 2) {
      return parts[0] + '.' + parts[1] + '.*.*';
    }
    return '';
  }
}