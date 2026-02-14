import { Component, inject } from '@angular/core';
import { LoginService } from '../services/login.service';
import { HomeComponent } from '../home/home.component';
import { LoginComponent } from '../login/login.component';

@Component({
  selector: 'app-root-page',
  standalone: true,
  template: `
    @if (isLogin()) {
      <app-home></app-home>
    } @else {
      <app-login></app-login>
    }
  `,
  imports: [HomeComponent, LoginComponent]
})
export class RootComponent {
  private loginService = inject(LoginService);
  isLogin = this.loginService.isLoginSignal;
}