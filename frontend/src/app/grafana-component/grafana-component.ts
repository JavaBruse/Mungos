import { Component, inject, OnInit, effect, signal } from '@angular/core';
import { StyleSwitcherService } from '../services/style-switcher.service';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { environment } from '../../environments/environment';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';


@Component({
  selector: 'app-grafana-component',
  imports: [MatIconModule, MatButtonModule, MatTooltipModule],
  templateUrl: './grafana-component.html',
  styleUrl: './grafana-component.scss',
})
export class GrafanaComponent implements OnInit {
  style = inject(StyleSwitcherService);
  private sanitizer = inject(DomSanitizer);
  private url = environment.apiUrl;
  public safeUrl: SafeResourceUrl | undefined;
  private theme = signal(this.style.themeSignal);
  public tooltipText = 'Развернуть';
  public isMaximized = false;
  tooltipVisible = false;

  showTooltip() {
    this.tooltipVisible = true;
  }
  hideTooltip() {
    this.tooltipVisible = false;
  }
  constructor() {
    effect(() => {
      this.theme.set(this.style.themeSignal);
      this.updateUrl();
    });
  }

  ngOnInit() {
    this.updateUrl();
  }

  private updateUrl() {
    const token = localStorage.getItem('Authorization');
    if (token) {
      document.cookie = `grafana_auth=${encodeURIComponent(token)}; path=/; SameSite=Lax`;
    }
    const baseUrl = this.url + "grafana/d/ad8mqvg?orgId=1&from=now-6h&to=now";
    const theme = this.theme() ? "light" : "dark";
    const url = `${baseUrl}&theme=${theme}`;
    this.safeUrl = this.sanitizer.bypassSecurityTrustResourceUrl(url);
  }

  toggleMaximize() {
    this.isMaximized = !this.isMaximized;
    this.tooltipText = this.isMaximized ? 'Свернуть' : 'Развернуть';
  }
}





// const baseUrl = this.url + "grafana/d/ad8mqvg?orgId=1";