import { Component, Input, Output, EventEmitter, inject, OnChanges, SimpleChanges } from '@angular/core';
import { FormBuilder, FormGroup, FormArray, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { SnifferService } from '../service/sniffer.service';
import { SnifferSetting } from '../service/sniffer-setting';
import { ErrorMessageService } from '../../services/error-message.service';

@Component({
  selector: 'app-sniffer-setting-component',
  imports: [
    CommonModule,
    ReactiveFormsModule,
    MatButtonModule,
    MatChipsModule,
    MatIconModule,
    MatInputModule,
    MatCheckboxModule
  ],
  templateUrl: './sniffer-setting-component.html',
  styleUrl: './sniffer-setting-component.scss',
})
export class SnifferSettingComponent implements OnChanges {
  @Input() snifferId: string | null = null;
  @Output() saved = new EventEmitter<void>();
  @Output() cancelled = new EventEmitter<void>();
  messageService = inject(ErrorMessageService);

  private snifferService = inject(SnifferService);
  private fb = inject(FormBuilder);

  setting: SnifferSetting | null = null;

  form: FormGroup = this.fb.group({
    BPFfilters: this.fb.array<string>([])
  });

  get filterArray(): FormArray {
    return this.form?.get('BPFfilters') as FormArray || this.fb.array([]);
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['snifferId'] && this.snifferId) {
      this.loadSetting();
    }
  }

  private loadSetting(): void {
    if (!this.snifferId) return;

    this.snifferService.getSetting(this.snifferId).subscribe(setting => {
      this.setting = setting;
      if (setting && this.form) {
        this.form.patchValue({
          id: setting.id
        });
        this.filterArray.clear();
        setting.filters?.forEach(word => this.filterArray.push(this.fb.control(word || '')));
      }
    });
  }


  addFilter(word: string) {
    const trimmed = word.trim();
    if (!trimmed) {
      this.messageService.showError('Значение не задано!');
      return;
    }

    // Регулярные выражения для проверки
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const portPattern = /^\d+$/;
    const ipPortPattern = /^(\d{1,3}\.){3}\d{1,3}:\d+$/;

    // Проверка IP адреса
    if (ipPattern.test(trimmed)) {
      const parts = trimmed.split('.');
      const valid = parts.every(part => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255;
      });
      if (!valid) {
        this.messageService.showError('Неверный IP адрес (октет должен быть от 0 до 255)');
        return;
      }
    }
    // Проверка порта
    else if (portPattern.test(trimmed)) {
      const port = parseInt(trimmed, 10);
      if (port < 1 || port > 65535) {
        this.messageService.showError('Порт должен быть от 1 до 65535');
        return;
      }
    }
    // Проверка комбинации IP:порт
    else if (ipPortPattern.test(trimmed)) {
      const [ip, portStr] = trimmed.split(':');
      const ipParts = ip.split('.');
      const ipValid = ipParts.every(part => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255;
      });
      const port = parseInt(portStr, 10);
      const portValid = port >= 1 && port <= 65535;

      if (!ipValid || !portValid) {
        this.messageService.showError('Неверный формат IP:порт');
        return;
      }
    }
    else {
      this.messageService.showError('Допустимы только IP адрес, порт или комбинация IP:порт');
      return;
    }

    const exists = this.filterArray.value.some(
      (w: string) => w.toLowerCase() === trimmed.toLowerCase()
    );
    if (exists) {
      this.messageService.showError('Это значение уже добавлено!');
      return;
    }

    this.filterArray.push(this.fb.control(trimmed));
  }

  removeWord(index: number) {
    this.filterArray.removeAt(index);
  }

  save() {
    if (!this.filterArray) return;
    if (!this.snifferId) return;
    if (this.form.invalid) {
      this.messageService.showError("Форма не заполнена или содержит ошибки");
      return;
    }

    if (this.filterArray.length === 0) {
      this.messageService.showError("Нет ключевых слов");
      return;
    }

    const updatedFilter: SnifferSetting = {
      id: this.snifferId,
      filters: this.filterArray.value,
      date: 0
    };

    this.snifferService.saveSetting(updatedFilter);
    this.saved.emit();
  }

  cancel(): void {
    this.cancelled.emit();
  }
}