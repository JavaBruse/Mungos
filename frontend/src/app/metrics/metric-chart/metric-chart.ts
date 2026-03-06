import { Component, Input, OnInit, OnDestroy, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NgxEchartsModule } from 'ngx-echarts';
import type { EChartsOption } from 'echarts';
import { Subscription, interval } from 'rxjs';
import { MetricService, MetricData } from '../metric.service';

@Component({
  selector: 'app-metric-chart',
  standalone: true,
  imports: [CommonModule, NgxEchartsModule],
  templateUrl: './metric-chart.html',
  styleUrls: ['./metric-chart.scss']
})
export class MetricChart implements OnInit, OnDestroy {
  @Input() query!: string;
  @Input() title: string = '';
  @Input() type: 'packets' | 'bytes' | 'cpu' | 'memory' | 'connections' | 'pps' | 'bps' = 'packets';
  @Input() snifferId?: string;
  @Input() height: string = '300px';
  @Input() refreshInterval: number = 15000;
  @Input() range: string = '30d';

  private metricService = inject(MetricService);
  private subscription?: Subscription;
  private dataCheckTimer: any;

  loading = false;
  error: string | null = null;
  hasData = false;
  chartOptions: EChartsOption = {};

  private readonly metricConfigs = {
    packets: { query: 'sniffer_packets_total', unit: 'packets' },
    bytes: { query: 'sniffer_bytes_total', unit: 'bytes' },
    cpu: { query: 'sniffer_cpu_usage', unit: '%', decimals: 2 },
    memory: { query: 'sniffer_memory_bytes', unit: 'MB', transform: (v: number) => v / 1024 / 1024 },
    connections: { query: 'sniffer_tcp_connections', unit: 'conn' },
    pps: { query: 'sniffer_packets_per_second', unit: 'pps' },
    bps: { query: 'sniffer_bytes_per_second', unit: 'B/s' }
  };

  ngOnInit() {
    this.loadData();
    if (this.refreshInterval > 0) {
      this.subscription = interval(this.refreshInterval).subscribe(() => this.loadData());
    }
  }

  ngOnDestroy() {
    this.subscription?.unsubscribe();
    if (this.dataCheckTimer) clearTimeout(this.dataCheckTimer);
  }

  private loadData() {
    const config = this.metricConfigs[this.type];
    if (!config) return;

    const fullQuery = this.snifferId
      ? `${config.query}{sniffer="${this.snifferId}"}`
      : config.query;

    const { start, end, step } = this.getTimeRange();

    this.metricService.clear();
    this.metricService.queryRange(fullQuery, start, end, step);

    if (this.dataCheckTimer) clearTimeout(this.dataCheckTimer);

    this.dataCheckTimer = setTimeout(() => {
      const metricsMap = this.metricService.metrics();
      this.loading = this.metricService.loading();
      this.error = this.metricService.error();

      const relevantData: MetricData[][] = [];
      metricsMap.forEach((value, key) => {
        if (key.startsWith(fullQuery)) relevantData.push(value);
      });

      this.hasData = relevantData.length > 0 && relevantData[0]?.length > 0;
      if (this.hasData) this.updateChart(relevantData, config);
    }, 200);
  }

  private updateChart(data: MetricData[][], config: any) {
    const series = data.map((values, i) => {
      let processedValues = values;
      if (config.transform) {
        processedValues = values.map(v => ({
          ...v,
          value: config.transform(v.value)
        }));
      }

      let seriesName = `Sniffer ${i + 1}`;
      if (!this.snifferId) {
        const key = Array.from(this.metricService.metrics().keys())[i] || '';
        const match = key.match(/sniffer="([^"]+)"/);
        if (match) seriesName = match[1];
      }

      const hue = (i * 35) % 360;
      const color = `hsl(${hue}, 70%, 60%)`;

      return {
        name: seriesName,
        type: 'line',
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 2, color },
        areaStyle: config.type === 'cpu' || config.type === 'memory' ? { opacity: 0.1, color } : undefined,
        data: processedValues.map(v => [v.time.getTime(), v.value])
      };
    });

    const valueFormatter = (value: any) => {
      if (value === null || value === undefined) return '—';
      const num = Number(value);
      if (isNaN(num)) return '—';
      if (config.decimals) return num.toFixed(config.decimals);
      return Math.round(num).toString();
    };

    this.chartOptions = {
      title: this.title ? { text: this.title, left: 'center', textStyle: { fontSize: 14, fontWeight: 'normal' } } : undefined,
      tooltip: { trigger: 'axis', valueFormatter },
      grid: { left: '5%', right: '5%', bottom: '10%', top: this.title ? '15%' : '10%', containLabel: true },
      xAxis: { type: 'time', boundaryGap: false, axisLabel: { fontSize: 11 } } as any,
      yAxis: { type: 'value', name: config.unit, nameTextStyle: { fontSize: 11 }, axisLabel: { fontSize: 11 } },
      series: series as any,
      dataZoom: [{ type: 'inside', start: 0, end: 100 }, { type: 'slider', start: 0, end: 100, height: 20 }],
      legend: {
        show: !this.snifferId && series.length > 1,
        type: 'scroll',
        bottom: 0,
        itemWidth: 15,
        itemHeight: 3
      },
      backgroundColor: 'transparent'
    };
  }

  private getTimeRange() {
    const end = new Date();
    const value = parseInt(this.range);
    let start: Date;

    if (this.range.endsWith('h')) start = new Date(end.getTime() - value * 60 * 60 * 1000);
    else if (this.range.endsWith('d')) start = new Date(end.getTime() - value * 24 * 60 * 60 * 1000);
    else if (this.range.endsWith('m')) start = new Date(end.getTime() - value * 60 * 1000);
    else start = new Date(end.getTime() - 60 * 60 * 1000);

    let step = '15s';
    if (value > 6 && this.range.endsWith('h')) step = '1m';
    if (value > 24 && this.range.endsWith('h')) step = '5m';
    if (this.range.endsWith('d')) step = value <= 1 ? '5m' : '15m';

    return { start, end, step };
  }
}