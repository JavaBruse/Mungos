import { Component, OnInit, OnDestroy, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { SnifferWebSocketService, TrafficPacket, TrafficRequest } from '../service/sniffer-websocket.service';
import { ActivatedRoute } from '@angular/router';
import { ScrollDispatcher } from '@angular/cdk/scrolling';
import { debounceTime, distinctUntilChanged } from 'rxjs/operators';
import { fromEvent, Subscription } from 'rxjs';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatDatepickerModule } from '@angular/material/datepicker';
import { provideNativeDateAdapter } from '@angular/material/core';
import { MAT_DATE_LOCALE } from '@angular/material/core';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatButtonModule } from '@angular/material/button';

@Component({
  selector: 'app-sniffer-websocket-component',
  standalone: true,
  providers: [
    provideNativeDateAdapter(),
    { provide: MAT_DATE_LOCALE, useValue: 'ru-RU' }
  ],
  imports: [
    CommonModule,
    ReactiveFormsModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatDatepickerModule,
    MatIconModule,
    MatTooltipModule,
    MatButtonModule

  ],
  templateUrl: './sniffer-websocket-component.html',
  styleUrl: './sniffer-websocket-component.scss',
})
export class SnifferWebsocketComponent implements OnInit, OnDestroy {
  private wsService = inject(SnifferWebSocketService);
  private route = inject(ActivatedRoute);
  private scrollDispatcher = inject(ScrollDispatcher);
  private fb = inject(FormBuilder);

  trafficData = signal<TrafficPacket[]>([]);
  expandedPacket = signal<number | null>(null);
  id = signal('');
  hasMore = signal(true);
  filterActive = signal(false);
  isLoading = signal(false);
  filterForm: FormGroup;

  availableProtocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'ARM', 'FTP', 'SSH', 'SMTP'];

  private readonly LIMIT = 1000;
  private windowScrollSubscription: any;
  private filterSubscription!: Subscription;
  private paramSubscription!: Subscription;

  constructor() {
    this.filterForm = this.fb.group({
      protocols: [[]],
      ports: [''],
      ips: [''],
      startTime: [null],
      endTime: [null],
      textSearch: ['']
    });
  }

  getKeys(obj: any): string[] {
    return obj ? Object.keys(obj) : [];
  }

  private parseFilterValues(): TrafficRequest {
    const formValues = this.filterForm.value;
    const request: TrafficRequest = {
      snifferId: this.id(),
      limit: this.LIMIT,
      offset: 0
    };

    if (formValues.protocols && formValues.protocols.length) {
      request.protocols = formValues.protocols;
    }
    if (formValues.ports) {
      request.ports = formValues.ports.split(',').map((s: string) => parseInt(s.trim(), 10)).filter((p: number) => !isNaN(p));
    }
    if (formValues.ips) {
      request.ips = formValues.ips.split(',').map((s: string) => s.trim());
    }


    if (formValues.startTime) {
      const startDate = new Date(formValues.startTime);
      startDate.setHours(0, 0, 0, 0);
      request.startTime = startDate.getTime() * 1000000;
    }

    if (formValues.endTime) {
      const endDate = new Date(formValues.endTime);
      endDate.setHours(23, 59, 59, 999);
      request.endTime = endDate.getTime() * 1000000;
    }



    if (formValues.textSearch) {
      request.textSearch = formValues.textSearch;
    }

    return request;
  }

  private checkFilterActive() {
    const values = this.filterForm.value;
    this.filterActive.set(
      (values.protocols && values.protocols.length > 0) ||
      !!values.ports || !!values.ips ||
      !!values.startTime || !!values.endTime || !!values.textSearch
    );
  }

  loadMore() {
    if (!this.hasMore()) return;

    const offset = this.wsService.getOffset(this.id());
    const request = this.parseFilterValues();
    request.offset = offset;

    this.wsService.requestTraffic(request);
  }

  resetAndLoad() {
    this.wsService.setOffset(this.id(), 0);
    // this.trafficData.set([]);
    this.isLoading.set(true);
    this.hasMore.set(true);
    this.loadMore();
  }

  loadInitial() {
    this.resetAndLoad();
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
    this.paramSubscription = this.route.paramMap.subscribe(params => {
      const newId = params.get('id')!;
      this.id.set(newId);
      this.wsService.setOffset(newId, 0);
      this.trafficData.set([]);
      this.hasMore.set(true);

      this.wsService.connect();
      this.setupSubscriptions();

      const connectionCheck = setInterval(() => {
        if (this.wsService.isConnected()) {
          this.wsService.subscribeToTraffic(this.id());
          this.loadInitial();
          clearInterval(connectionCheck);
        }
      }, 500);
    });

    this.filterSubscription = this.filterForm.valueChanges
      .pipe(
        debounceTime(500),
        distinctUntilChanged((prev, curr) => JSON.stringify(prev) === JSON.stringify(curr))
      )
      .subscribe(() => {
        this.checkFilterActive();
        this.resetAndLoad();
      });

    this.windowScrollSubscription = fromEvent(window, 'scroll')
      .pipe(debounceTime(200))
      .subscribe(() => {
        const scrollPosition = window.scrollY + window.innerHeight;
        const documentHeight = document.documentElement.scrollHeight;

        if (scrollPosition >= documentHeight - 200 && this.hasMore()) {
          this.loadMore();
        }
      });
  }

  private setupSubscriptions() {
    if (this.subscriptions.length) {
      this.subscriptions.forEach(sub => sub.unsubscribe());
    }

    this.subscriptions = [
      this.wsService.packets$.subscribe(packet => {
        if (this.isLoading()) {
          this.trafficData.set([packet]);
          this.isLoading.set(false);
        } else {
          this.trafficData.update(data => [...data, packet]);
        }
      }),

      this.wsService.complete$.subscribe(total => {
        const newOffset = this.wsService.getOffset(this.id()) + total;
        this.wsService.setOffset(this.id(), newOffset);

        if (total < this.LIMIT) {
          this.hasMore.set(false);
        }
      }),

      this.wsService.error$.subscribe(error => {
        console.error('Error:', error);
      })
    ];
  }

  loadPayload(packet: TrafficPacket) {
    if (packet.payload || !packet.hasPayload) return;

    packet.loadingPayload = true;

    const subscription = this.wsService.getPayload$(packet.packetId).subscribe({
      next: (payload) => {
        packet.payload = payload;
        packet.loadingPayload = false;
      },
      error: () => packet.loadingPayload = false
    });

    this.wsService.requestPayload(this.id(), packet.packetId);
  }

  formatPayload(payload: string): string {
    if (!payload) return '';
    return Array.from(new TextEncoder().encode(payload))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');
  }

  ngOnDestroy() {
    if (this.windowScrollSubscription) {
      this.windowScrollSubscription.unsubscribe();
    }
    if (this.filterSubscription) {
      this.filterSubscription.unsubscribe();
    }
    if (this.paramSubscription) {
      this.paramSubscription.unsubscribe();
    }
    this.subscriptions.forEach(sub => sub.unsubscribe());
    this.wsService.disconnect();
    this.wsService.clearOffset(this.id());
  }
  private subscriptions: any[] = [];

  clearFilters() {
    this.filterForm.patchValue({
      protocols: [],
      ports: '',
      ips: '',
      startTime: null,
      endTime: null,
      textSearch: ''
    });
  }

  togglePayload(packet: TrafficPacket) {
    if (packet.payload) {
      packet.payload = undefined;
    } else {
      if (!packet.hasPayload) return;

      this.wsService.loadingService.setLoading(true);

      this.wsService.getPayload$(packet.packetId).subscribe({
        next: (payload) => {
          packet.payload = payload;
          this.wsService.loadingService.setLoading(false);
        },
        error: () => {
          this.wsService.loadingService.setLoading(false);
        }
      });

      this.wsService.requestPayload(this.id(), packet.packetId);
    }
  }
}