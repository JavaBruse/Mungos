import { Component, inject, signal } from '@angular/core';
import { FormGroup, FormControl } from '@angular/forms';
import { ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { lastValueFrom } from 'rxjs';
import { HttpService } from '../services/http.service';
import { ErrorMessageService } from '../services/error-message.service';
import { environment } from '../../environments/environment';
import { LoginService } from '../services/login.service';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';


@Component({
  selector: 'app-login',
  imports: [ReactiveFormsModule, MatFormFieldModule, MatInputModule, MatIconModule, MatButtonModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css',
})

export class LoginComponent {
  profileForm = new FormGroup({
    login: new FormControl('', Validators.required),
    passwd: new FormControl('', [Validators.required]),
  });
  router = inject(Router);
  http = inject(HttpService);
  loginService = inject(LoginService);
  errorMessageService = inject(ErrorMessageService);

  private url = environment.apiUrl;

  async onSubmit() {
    if (this.profileForm.invalid) {
      this.errorMessageService.showError('Форма не заполнена!');
      return;
    }
    const urls = this.url + 'security/auth/sign-in';
    const authData = {
      username: this.profileForm.value.login,
      password: this.profileForm.value.passwd
    };

    try {
      const response: any = await lastValueFrom(this.http.post<{ token: string }>(urls, authData));
      localStorage.setItem('Authorization', `Bearer ${response.token}`);
      this.loginService.setIsLoginSignal(true);
      this.router.navigate(['stats']);

    } catch (error) {
      this.errorMessageService.showError('"Отказано в доступе"');
    }
  }
  closeWindow() {
    this.router.navigateByUrl('/'); // Замените на путь к нужной странице
  }
  hide = signal(true);
  clickEvent(event: MouseEvent) {
    this.hide.set(!this.hide());
    event.stopPropagation();
  }
}
