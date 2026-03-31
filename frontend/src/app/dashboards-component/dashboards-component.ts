import { Component, inject, OnInit } from '@angular/core';
import { StyleSwitcherService } from '../services/style-switcher.service';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { environment } from '../../environments/environment';

@Component({
  selector: 'app-dashboards-component',
  imports: [],
  templateUrl: './dashboards-component.html',
  styleUrl: './dashboards-component.scss',
})
export class DashboardsComponent implements OnInit {
  style = inject(StyleSwitcherService);
  private sanitizer = inject(DomSanitizer);
  private url = environment.apiUrl;
  public safeUrl: SafeResourceUrl | undefined;

  ngOnInit() {
    this.safeUrl = this.generateGrafanaUrl();
  }

  private generateGrafanaUrl(): SafeResourceUrl {
    const token = localStorage.getItem('Authorization');
    if (token) {
      document.cookie = `grafana_auth=${encodeURIComponent(token)}; path=/; SameSite=Lax`;
    }

    const baseUrl = this.url + "grafana/d/ad8mqvg/mungos?orgId=1&from=now-6h&to=now&timezone=browser&refresh=5s&kiosk";
    const theme = this.style.themeSignal ? "light" : "dark";
    const url = `${baseUrl}&theme=${theme}`;

    return this.sanitizer.bypassSecurityTrustResourceUrl(url);
  }
}