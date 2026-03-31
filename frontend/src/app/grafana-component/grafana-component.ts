import { Component, inject, OnInit } from '@angular/core';
import { StyleSwitcherService } from '../services/style-switcher.service';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { environment } from '../../environments/environment';

@Component({
  selector: 'app-grafana-component',
  imports: [],
  templateUrl: './grafana-component.html',
  styleUrl: './grafana-component.scss',
})
export class GrafanaComponent implements OnInit {
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

    const baseUrl = this.url + "grafana/d/ad8mqvg?orgId=1";
    const theme = this.style.themeSignal ? "light" : "dark";
    const url = `${baseUrl}&theme=${theme}`;

    return this.sanitizer.bypassSecurityTrustResourceUrl(url);
  }
}