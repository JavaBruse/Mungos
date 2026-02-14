import { Component, inject, signal, effect, OnDestroy } from '@angular/core';
import { ErrorMessageService, Message } from '../services/error-message.service';

@Component({
  selector: 'app-error-message',
  standalone: true,
  templateUrl: './error-message.component.html',
  styleUrl: './error-message.component.css',
})
export class ErrorMessageComponent implements OnDestroy {
  private svc = inject(ErrorMessageService);
  visibleMessage = signal<Message | null>(null);
  leaving = signal(false);

  private hideTimer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    effect(() => {
      const msg = this.svc.message$();
      if (msg) {
        if (this.hideTimer) {
          clearTimeout(this.hideTimer);
          this.hideTimer = null;
        }
        this.leaving.set(false);
        this.visibleMessage.set(msg);

        // Автоматическое скрытие через разное время в зависимости от типа
        const hideTime = this.getHideTime(msg.type);
        this.hideTimer = setTimeout(() => {
          this.startHideAnimation();
        }, hideTime);
      } else {
        if (this.visibleMessage()) {
          this.startHideAnimation();
        }
      }
    });
  }

  private getHideTime(type: string): number {
    switch (type) {
      case 'success': return 3000; // 3 секунды для успешных
      case 'error': return 5000;   // 5 секунд для ошибок
      case 'warning': return 4000; // 4 секунды для предупреждений
      case 'info': return 3000;    // 3 секунды для информации
      default: return 3000;
    }
  }

  private startHideAnimation() {
    this.leaving.set(true);
    if (this.hideTimer) clearTimeout(this.hideTimer);
    this.hideTimer = setTimeout(() => {
      this.visibleMessage.set(null);
      this.leaving.set(false);
      this.hideTimer = null;
    }, 500);
  }

  closeMessage() {
    this.svc.clearMessage();
  }

  ngOnDestroy() {
    if (this.hideTimer) clearTimeout(this.hideTimer);
  }
}