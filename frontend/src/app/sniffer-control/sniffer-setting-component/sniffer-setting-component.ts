import { Component, Input, Output, EventEmitter, inject, OnChanges, SimpleChanges, effect } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
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
    filters: ""
  });

  constructor() {
    effect(() => {
      const setting = this.snifferService.snifferSetting();
      if (setting && this.form && !this.form.dirty) {
        this.form.patchValue({
          filters: setting.filters
        });
      }
    });
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['snifferId'] && this.snifferId) {
      this.loadSetting();
    }
  }

  private loadSetting(): void {
    if (!this.snifferId) return;
    this.snifferService.getSetting(this.snifferId);
  }

  save() {
    if (!this.snifferId) return;

    const updatedFilter: SnifferSetting = {
      id: this.snifferId,
      filters: this.form.value.filters,
      date: 0
    };

    this.snifferService.saveSetting(updatedFilter);
    this.saved.emit();
    this.cancel();
  }

  cancel(): void {
    this.cancelled.emit();
  }
}