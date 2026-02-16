import { Component, inject, signal } from '@angular/core';
import { FormGroup, FormControl } from '@angular/forms';
import { ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { lastValueFrom } from 'rxjs';
import { environment } from '../../environments/environment';
import { HttpService } from '../services/http.service';
import { ErrorMessageService } from '../services/error-message.service';
import { LoginService } from '../services/login.service';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-first-login-password',
  imports: [ReactiveFormsModule, MatFormFieldModule, MatInputModule, MatButtonModule, MatIconModule],
  templateUrl: './first-login-password.html',
  styleUrl: './first-login-password.scss',
})
export class FirstLoginPassword {
  profileForm = new FormGroup({
    login: new FormControl('', Validators.required),
    fullName: new FormControl(''),
    passwd: new FormControl('', [Validators.required]),
  });
  router = inject(Router);
  http = inject(HttpService);
  loginService = inject(LoginService);
  errorMessageService = inject(ErrorMessageService);
  private url = environment.apiUrl;

  errorMessage = signal('');

  constructor() {
    this.profileForm.patchValue({
      login: this.loginService.userData().username,
      fullName: this.loginService.userData().fullName,
    });
  }

  async onSubmit() {
    if (this.profileForm.invalid) {
      this.errorMessageService.showError('Не корректно заполнена форма!');
      return;
    }

    const urls = this.url + 'api/v1/auth/update-in';
    const authData = {
      username: this.profileForm.value.login,
      fullName: this.profileForm.value.fullName,
      password: this.profileForm.value.passwd
    };
    try {
      const response: any = await lastValueFrom(this.http.post<{ token: string }>(urls, authData));
      localStorage.setItem('Authorization', `Bearer ${response.token}`);
      this.router.navigate(['stats']);
      this.loginService.updateUserData()
    } catch (error) {
      this.errorMessageService.showError("Ошибка обновления данных!");
    }
  }

  closeWindow() {
    this.router.navigateByUrl('/');
  }

  hide = signal(true);
  clickEvent(event: MouseEvent) {
    this.hide.set(!this.hide());
    event.stopPropagation();
  }
}
