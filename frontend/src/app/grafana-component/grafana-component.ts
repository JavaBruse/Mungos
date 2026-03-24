import { Component, inject } from '@angular/core';
import { StyleSwitcherService } from '../services/style-switcher.service';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';

@Component({
  selector: 'app-grafana-component',
  imports: [],
  templateUrl: './grafana-component.html',
  styleUrl: './grafana-component.scss',
})
export class GrafanaComponent {
  style = inject(StyleSwitcherService);
  private sanitizer = inject(DomSanitizer);

  getGrafanaUrl(): SafeResourceUrl {
    const baseUrl = "http://localhost:3000/d/ad8mqvg?orgId=1";
    const theme = this.style.themeSignal ? "light" : "dark";
    const url = `${baseUrl}&theme=${theme}`;
    return this.sanitizer.bypassSecurityTrustResourceUrl(url);
  }
}