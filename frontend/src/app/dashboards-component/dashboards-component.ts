import { Component, inject } from '@angular/core';
import { StyleSwitcherService } from '../services/style-switcher.service';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';


@Component({
  selector: 'app-dashboards-component',
  imports: [],
  templateUrl: './dashboards-component.html',
  styleUrl: './dashboards-component.scss',
})
export class DashboardsComponent {
  style = inject(StyleSwitcherService);
  private sanitizer = inject(DomSanitizer);

  getGrafanaUrl(): SafeResourceUrl {
    const baseUrl = "http://localhost:3000/d/ad8mqvg?orgId=1&from=1774076801762&to=1774088611286&timezone=browser&refresh=5s&kiosk";
    const theme = this.style.themeSignal ? "light" : "dark";
    const url = `${baseUrl}&theme=${theme}`;
    return this.sanitizer.bypassSecurityTrustResourceUrl(url);
  }
}
