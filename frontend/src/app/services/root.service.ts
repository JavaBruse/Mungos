import { Component, inject } from '@angular/core';
import { LoginService } from '../services/login.service';
import { HomeComponent } from '../home/home.component';
import { LoginComponent } from '../login/login.component';
import { FirstLoginPassword } from '../first-login-password/first-login-password';


@Component({
  selector: 'app-root-page',
  standalone: true,
  template: `
    @if (loginService.userData().isLogin && loginService.userData().isUpdated) {
      <app-home></app-home>
    } @else if (loginService.userData().isLogin && !loginService.userData().isUpdated) {
      <app-first-login-password></app-first-login-password>
    } @else {
      <app-login></app-login>
    }
  `,
  imports: [HomeComponent, LoginComponent, FirstLoginPassword]
})
export class RootComponent {
  protected loginService = inject(LoginService);
}