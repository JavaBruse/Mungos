import { Component, inject, signal } from '@angular/core';
import { ErrorMessageService } from '../../services/error-message.service';
import { FormBuilder, FormGroup, FormArray, Validators, ReactiveFormsModule, FormControl } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatSelectModule } from '@angular/material/select';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatCardModule } from '@angular/material/card';
import { UserService } from '../service/user.service';
import { UserRequestDTO } from '../service/user-request.DTO';


@Component({
  selector: 'app-user-add-component',
  imports: [
    ReactiveFormsModule,
    MatButtonModule,
    MatChipsModule,
    MatIconModule,
    MatInputModule,
    MatCheckboxModule,
    MatSelectModule,
    MatFormFieldModule,
    MatCardModule
  ],
  templateUrl: './user-add-component.html',
  styleUrl: './user-add-component.scss',
})
export class UserAddComponent {
  private fb = inject(FormBuilder);
  userService = inject(UserService);
  private errorMessageService = inject(ErrorMessageService);


  form: FormGroup = this.fb.group({
    username: new FormControl<string | null>(null),
    fullName: new FormControl<string | null>(null),
    password: new FormControl<string | null>(null),
    role: new FormControl<string | null>(null)
  });

  hide = signal(true);
  clickEvent(event: MouseEvent) {
    this.hide.set(!this.hide());
    event.stopPropagation();
  }

  save() {
    const username = this.form.value.username;
    const fullName = this.form.value.fullName;
    const password = this.form.value.password;
    const role = this.form.value.role;

    if (!username) return this.errorMessageService.showError("Поле Login не заполнено");
    if (!fullName) return this.errorMessageService.showError("Полное имя не заполнено");
    if (!password) return this.errorMessageService.showError("Пароль не задан");
    if (!role) return this.errorMessageService.showError("Роль не выбрана");
    if (username.length < 5 || username.length > 50) {
      return this.errorMessageService.showError("Логин должен содержать от 5 до 50 символов");
    }
    if (password.length < 5 || password.length > 50) {
      return this.errorMessageService.showError("Пароль должен содержать от 5 до 50 символов");
    }

    if (!/^[A-Za-z]+$/.test(username)) {
      return this.errorMessageService.showError("Логин должен содержать только латинские буквы");
    }

    if (!/^[A-Za-z0-9]+$/.test(password)) {
      return this.errorMessageService.showError("Пароль должен содержать только латинские буквы и цифры");
    }

    const userData: UserRequestDTO = {
      username: username,
      fullname: fullName,
      password: password,
      role: role
    };

    this.userService.add(userData);
    this.cancel();
  }

  cancel() {
    this.userService.setVisibleAdd(false);
  }

}
