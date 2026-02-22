import { Component, OnInit, OnDestroy, inject, signal, ViewChild, ElementRef, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SnifferWebSocketService, TrafficPacket, TrafficRequest } from '../service/sniffer-websocket.service';
import { ActivatedRoute } from '@angular/router';
import { ScrollDispatcher } from '@angular/cdk/scrolling';
import { debounceTime } from 'rxjs/operators';
import { fromEvent } from 'rxjs';

@Component({
  selector: 'app-sniffer-websocket-component',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './sniffer-websocket-component.html',
  styleUrl: './sniffer-websocket-component.scss',
})
export class SnifferWebsocketComponent implements OnInit, OnDestroy {
  private wsService = inject(SnifferWebSocketService);
  private route = inject(ActivatedRoute);
  private scrollDispatcher = inject(ScrollDispatcher);


  trafficData = signal<TrafficPacket[]>([]);
  expandedPacket = signal<number | null>(null);
  loading = signal(false);
  id = signal('');
  hasMore = signal(true);

  private readonly LIMIT = 1000;
  private windowScrollSubscription: any;

  getKeys(obj: any): string[] {
    return obj ? Object.keys(obj) : [];
  }

  loadMore() {
    if (!this.hasMore() || this.loading()) return;

    this.loading.set(true);
    const offset = this.wsService.getOffset(this.id());

    const request: TrafficRequest = {
      snifferId: this.id(),
      limit: this.LIMIT,
      offset: offset
    };

    this.wsService.requestTraffic(request);
  }

  loadInitial() {
    this.loadMore();
  }

  togglePacket(index: number) {
    this.expandedPacket.set(this.expandedPacket() === index ? null : index);
  }

  formatTimestamp(timestamp: number): string {
    return new Date(timestamp / 1000000).toLocaleString();
  }

  getPacketSummary(packet: TrafficPacket): string {
    const parts = [];
    if (packet.srcIp && packet.dstIp) {
      parts.push(`${packet.srcIp}:${packet.srcPort} → ${packet.dstIp}:${packet.dstPort}`);
    }
    if (packet.method && packet.uri) {
      parts.push(`${packet.method} ${packet.uri}`);
    } else if (packet.dnsQuery) {
      parts.push(`DNS: ${packet.dnsQuery}`);
    }
    return parts.join(' - ') || 'No details';
  }


  ngOnInit() {
    this.route.paramMap.subscribe(params => {
      const newId = params.get('id')!;
      this.id.set(newId);

      this.wsService.setOffset(newId, 0);
      this.trafficData.set([]);
      this.hasMore.set(true);

      this.wsService.connect();
      this.setupSubscriptions();

      // Ждем подключения
      const connectionCheck = setInterval(() => {
        if (this.wsService.isConnected()) {
          this.wsService.subscribeToTraffic(this.id());
          this.loadInitial();
          clearInterval(connectionCheck);
        }
      }, 500);
    });

    // Добавляем обработчик скролла окна
    this.windowScrollSubscription = fromEvent(window, 'scroll')
      .pipe(debounceTime(200))
      .subscribe(() => {
        const scrollPosition = window.scrollY + window.innerHeight;
        const documentHeight = document.documentElement.scrollHeight;

        if (scrollPosition >= documentHeight - 200 && this.hasMore() && !this.loading()) {
          this.loadMore();
        }
      });
  }

  private setupSubscriptions() {
    // очистка старых подписок
    if (this.subscriptions.length) {
      this.subscriptions.forEach(sub => sub.unsubscribe());
    }

    this.subscriptions = [
      this.wsService.packets$.subscribe(packet => {
        this.trafficData.update(data => [...data, packet]);
      }),

      this.wsService.complete$.subscribe(total => {
        // Всегда увеличиваем offset на полученное количество
        const newOffset = this.wsService.getOffset(this.id()) + total;
        this.wsService.setOffset(this.id(), newOffset);

        if (total < this.LIMIT) {
          this.hasMore.set(false);
        }
        this.loading.set(false);
      }),

      this.wsService.error$.subscribe(error => {
        console.error('Error:', error);
        this.loading.set(false);
      })
    ];
  }

  loadPayload(packet: TrafficPacket) {
    if (packet.payload || !packet.hasPayload) return;

    packet.loadingPayload = true;

    // Сначала создаем подписку
    const subscription = this.wsService.getPayload$(packet.packetId).subscribe({
      next: (payload) => {
        packet.payload = payload;
        packet.loadingPayload = false;
      },
      error: () => packet.loadingPayload = false
    });

    // Потом отправляем запрос
    this.wsService.requestPayload(this.id(), packet.packetId);
  }
  formatPayload(payload: string): string {
    if (!payload) return '';

    // Конвертируем строку в массив байт и в HEX
    return Array.from(new TextEncoder().encode(payload))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');
  }

  ngOnDestroy() {
    if (this.windowScrollSubscription) {
      this.windowScrollSubscription.unsubscribe();
    }
    this.subscriptions.forEach(sub => sub.unsubscribe());
    this.wsService.disconnect();
    this.wsService.clearOffset(this.id());
  }
  private subscriptions: any[] = [];

}