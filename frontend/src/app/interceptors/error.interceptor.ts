import { HttpErrorResponse, HttpEvent, HttpHandlerFn, HttpRequest, HttpResponse } from '@angular/common/http';
import { HttpInterceptorFn } from '@angular/common/http';
import { throwError } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';
import { ErrorMessageService } from '../services/error-message.service';
import { inject } from '@angular/core';

// Вспомогательная функция для успешных сообщений
function getSuccessMessage(method: string | null, status: number): string | null {
    if (!method) return null;

    switch (method.toUpperCase()) {
        case 'POST':
            return status === 201 ? 'Успешно создано' : 'Успешно добавлено';
        case 'PUT':
            return 'Успешно обновлено';
        case 'PATCH':
            return 'Успешно обновлено';
        case 'DELETE':
            return 'Успешно удалено';
        default:
            return null;
    }
}

export const ErrorInterceptor: HttpInterceptorFn = (req, next) => {
    const errorMessageService = inject(ErrorMessageService);

    return next(req).pipe(
        tap(event => {
            // Обработка успешных ответов
            if (event instanceof HttpResponse) {
                // Можно добавить логику для успешных операций
                // Например, для POST, PUT, DELETE запросов показывать успешное уведомление
                if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE' || req.method === 'PATCH') {
                    const successMessage = getSuccessMessage(req.method, event.status);
                    if (successMessage) {
                        errorMessageService.showSuccess(successMessage);
                    }
                }

                // Для специфичных статусов
                if (event.status === 201 && req.method !== 'POST') {
                    errorMessageService.showSuccess('Успешно создано');
                }
            }
        }),
        catchError((error: HttpErrorResponse) => {
            let errorMessage = error.error?.message || 'Произошла ошибка';

            // console.error('HTTP Error:', error);

            // Определяем тип уведомления по статусу
            if (error.status >= 400 && error.status < 500) {
                if (error.status === 401) {
                    errorMessageService.showWarning('Неавторизованный доступ');
                } else if (error.status === 403) {
                    errorMessageService.showWarning('Доступ запрещен');
                } else if (error.status === 404) {
                    errorMessageService.showWarning('Ресурс не найден');
                } else if (error.status === 422) {
                    errorMessageService.showWarning('Некорректные данные');
                } else {
                    errorMessageService.showError(errorMessage);
                }
            } else if (error.status >= 500) {
                errorMessageService.showError('Серверная ошибка. Попробуйте позже');
            } else if (error.status === 0) {
                errorMessageService.showError('Нет соединения с сервером');
            } else {
                errorMessageService.showError(errorMessage);
            }

            return throwError(() => ({
                status: error.status,
                message: errorMessage,
                error: error.error
            }));
        })
    );
};