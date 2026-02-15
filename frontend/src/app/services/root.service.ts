import { Component, inject } from '@angular/core';
import { LoginService } from '../services/login.service';
import { HomeComponent } from '../home/home.component';
import { LoginComponent } from '../login/login.component';
import { FirstLoginPassword } from '../first-login-password/first-login-password';
import { Router, RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root-page',
  standalone: true,
  template: `<router-outlet></router-outlet>`, // Просто выводим текущий маршрут
  imports: [RouterOutlet] // Добавь RouterOutlet в imports
})
export class RootComponent {
  private loginService = inject(LoginService);
  private router = inject(Router);

  constructor() {
    const user = this.loginService.userData();

    if (!user.isLogin) {
      this.router.navigate(['/login']);
    } else if (!user.isUpdated) {
      this.router.navigate(['/update-password']);
    } else {
      this.router.navigate(['/home']);
    }
  }
}