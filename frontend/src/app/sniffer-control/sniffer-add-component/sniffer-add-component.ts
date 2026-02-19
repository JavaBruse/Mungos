import { Component, inject, signal } from '@angular/core';
import { ErrorMessageService } from '../../services/error-message.service';
import { FormBuilder, FormGroup, ReactiveFormsModule, FormControl, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatSelectModule } from '@angular/material/select';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatCardModule } from '@angular/material/card';
import { SnifferService } from '../service/sniffer.service';
import { SnifferRequestDTO } from '../service/sniffer-request.DTO';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-sniffer-add-component',
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
  templateUrl: './sniffer-add-component.html',
  styleUrl: './sniffer-add-component.scss',
})
export class SnifferAddComponent {
  private env = environment;
  private fb = inject(FormBuilder);
  snifferuserService = inject(SnifferService);
  private errorMessageService = inject(ErrorMessageService);

  form: FormGroup;

  constructor() {
    this.form = this.fb.group({
      name: [null, [Validators.required, Validators.minLength(2)]],
      location: [null, [Validators.required, Validators.minLength(2)]],
      host: [this.env.SNIFFER_NAME, [Validators.required, Validators.pattern(/^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,200}[a-zA-Z0-9]$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^localhost$/)]],
      port: [this.env.portSniffer, [Validators.required, Validators.min(1), Validators.max(65535), Validators.pattern(/^\d+$/)]]
    });
  }

  save() {
    if (this.form.invalid) {
      this.form.markAllAsTouched();

      if (this.form.get('name')?.errors) {
        this.errorMessageService.showError('Имя обязательно и должно содержать минимум 2 символа');
        return;
      }
      if (this.form.get('location')?.errors) {
        this.errorMessageService.showError('Локация обязательна и должна содержать минимум 2 символа');
        return;
      }
      if (this.form.get('host')?.errors) {
        this.errorMessageService.showError('Хост обязателен и должен быть корректным IP или доменом');
        return;
      }
      if (this.form.get('port')?.errors) {
        this.errorMessageService.showError('Порт обязателен и должен быть числом от 1 до 65535');
        return;
      }

      this.errorMessageService.showError('Заполните все поля корректно');
      return;
    }

    const snifferData: SnifferRequestDTO = {
      name: this.form.value.name,
      location: this.form.value.location,
      host: this.form.value.host,
      port: this.form.value.port,
    };

    this.snifferuserService.add(snifferData);
    this.cancel();
  }

  cancel() {
    this.snifferuserService.setVisibleAdd(false);
  }
}
