import { Component, OnInit, OnDestroy, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SnifferWebSocketService } from '../service/sniffer-websocket.service';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-sniffer-websocket-component',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './sniffer-websocket-component.html',
  styleUrl: './sniffer-websocket-component.scss',
})
export class SnifferWebsocketComponent implements OnInit, OnDestroy {
  trafficData: any[] = [];
  expandedPacket: number | null = null;
  loading = false;
  private route = inject(ActivatedRoute)
  private wsService = inject(SnifferWebSocketService);
  private id!: string;

  loadMore() {
    this.loading = true;
    this.wsService.requestTraffic(this.id, 'next');
  }

  togglePacket(index: number) {
    this.expandedPacket = this.expandedPacket === index ? null : index;
  }

  ngOnInit() {
    this.route.paramMap.subscribe(params => {
      this.id = params.get('id')!;
      this.wsService.connect();
    });
  }

  ngOnDestroy() {
    this.wsService.disconnect();
  }
}