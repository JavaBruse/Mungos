import { Component, Input, Output, EventEmitter, inject, SimpleChanges } from '@angular/core';
import { ErrorMessageService } from '../../services/error-message.service';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatChipsModule } from '@angular/material/chips';
import { FormBuilder, FormGroup, FormControl, Validators, ReactiveFormsModule } from '@angular/forms';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { UserService } from '../service/user.service';

@Component({
  selector: 'app-user-edit-component',
  imports: [
    ReactiveFormsModule,
    MatCardModule,
    MatChipsModule,
    MatIconModule,
    MatInputModule,
    MatFormFieldModule,
    MatSelectModule,
    MatButtonModule
  ],
  templateUrl: './user-edit-component.html',
  styleUrl: './user-edit-component.scss',
})
export class UserEditComponent {
  @Input() user: any | null = null;
  @Output() saved = new EventEmitter<void>();
  @Output() cancelled = new EventEmitter<void>();

  errorMessageService = inject(ErrorMessageService);
  userService = inject(UserService);
  private fb = inject(FormBuilder);

  form: FormGroup = this.fb.group({
    username: new FormControl<string | null>({ value: null, disabled: true }),
    fullName: new FormControl<string | null>(null, Validators.required),
    role: new FormControl<string | null>(null, Validators.required)
  });

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['user'] && this.user) {
      this.form.patchValue({
        username: this.user?.username ?? null,
        fullName: this.user?.fullName ?? null,
        role: this.user?.role ?? null
      }, { emitEvent: false });
    }
  }

  save() {
    if (this.form.invalid) {
      this.errorMessageService.showError("Форма не заполнена или содержит ошибки");
      return;
    }

    try {
      if (this.user?.id) {
        const userData = {
          fullName: this.form.value.fullName,
          role: this.form.value.role
        };

        // тут будет вызов метода обновления пользователя
        // this.userService.update(this.user.id, userData).subscribe(() => {
        //   this.saved.emit();
        //   this.cancel();
        // });

        this.saved.emit();
        this.cancel();
      }
    } catch (error: any) {
      this.errorMessageService.showError(error.message);
    }
  }

  cancel() {
    this.cancelled.emit();
  }
}