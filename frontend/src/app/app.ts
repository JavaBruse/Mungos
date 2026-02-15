import { Component, inject } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { StyleSwitcherService } from './services/style-switcher.service';
import { RouterOutlet, RouterModule, Router } from '@angular/router';
import { LoadingComponent } from './loading/loading.component';
import { LoginService } from './services/login.service';
import { ErrorMessageComponent } from './error-message/error-message.component';



@Component({
  selector: 'app-root',
  imports: [
    MatIconModule,
    RouterOutlet,
    RouterModule,
    LoadingComponent,
    ErrorMessageComponent
  ],
  templateUrl: './app.html',
  styleUrl: './app.scss'
})
export class App {
  menuVisible = false;
  isLightTheme = false;
  router = inject(Router);
  loginService = inject(LoginService);
  styleSwither = inject(StyleSwitcherService);

  constructor() {
    const savedTheme = (localStorage.getItem('theme') as 'light' | 'dark') || 'light';
    this.styleSwither.switchTheme(savedTheme);
  }

  ngOnInit() {
    this.isLightTheme = this.styleSwither.themeSignal;
  }

  closeMenu() {
    this.menuVisible = false;
  }

  toggleMenu(event?: Event) {
    if (event) event.stopPropagation();
    if (this.styleSwither.isMobileViewSignal()) this.menuVisible = !this.menuVisible;
  }

  onThemeSwitchChange() {
    const newTheme = this.styleSwither.themeSignal ? 'dark' : 'light';
    this.styleSwither.switchTheme(newTheme);
    this.isLightTheme = this.styleSwither.themeSignal;
  }

  logout() {
    localStorage.removeItem('Authorization');
    this.loginService.updateUserData();
    this.closeMenu();
  }

  isRouteActive(route: string): boolean {
    return this.router.url.includes(route);
  }
}

