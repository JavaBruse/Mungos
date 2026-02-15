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
import { merge } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

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

  async onSubmit() {
    if (this.profileForm.invalid) {
      this.errorMessageService.showError('Не корректно заполнена форма!');
      return;
    }

    const urls = this.url + 'security/auth/update-in';
    const authData = {
      username: this.profileForm.value.login,
      fullName: this.profileForm.value.fullName,
      password: this.profileForm.value.passwd
    };
    console.log(authData)
    try {
      const response: any = await lastValueFrom(this.http.post<{ token: string }>(urls, authData));
      localStorage.setItem('Authorization', `Bearer ${response.token}`);
      this.router.navigate(['stats']);
      this.loginService.updateUserData()
    } catch (error) {
      this.errorMessageService.showError("Ошибка регистрации!");
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



  readonly email = new FormControl('', [Validators.required, Validators.email]);

  errorMessage = signal('');

  constructor() {
    merge(this.email.statusChanges, this.email.valueChanges)
      .pipe(takeUntilDestroyed())
      .subscribe(() => this.updateErrorMessage());
  }

  updateErrorMessage() {
    if (this.email.hasError('Обязательно')) {
      this.errorMessage.set('Необходимо ввести ФИО');
    } else if (this.email.hasError('fullName')) {
      this.errorMessage.set('Некорректный ввод');
    } else {
      this.errorMessage.set('');
    }
  }
}
