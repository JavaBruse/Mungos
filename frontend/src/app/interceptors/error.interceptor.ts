import { HttpErrorResponse, HttpInterceptorFn, HttpResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { throwError } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';
import { ErrorMessageService } from '../services/error-message.service';

export const ErrorInterceptor: HttpInterceptorFn = (req, next) => {
    const errorMessageService = inject(ErrorMessageService);

    return next(req).pipe(
        tap(event => {
            if (event instanceof HttpResponse) {
                // Только для мутирующих запросов показываем success
                if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') {
                    const message = getSuccessMessage(req, event);
                    if (message) {
                        errorMessageService.showSuccess(message);
                    }
                }
            }
        }),
        catchError((error: HttpErrorResponse) => {
            const message = getErrorMessage(error);

            if (error.status >= 400 && error.status < 500) {
                if (error.status === 401) {
                    errorMessageService.showWarning('Неавторизованный доступ');
                } else if (error.status === 403) {
                    errorMessageService.showWarning('Доступ запрещен');
                } else if (error.status === 404) {
                    errorMessageService.showWarning('Ресурс не найден');
                } else {
                    errorMessageService.showError(message);
                }
            } else if (error.status >= 500) {
                errorMessageService.showError(message);
            } else if (error.status === 0) {
                errorMessageService.showError('Нет соединения с сервером');
            } else {
                errorMessageService.showError(message);
            }

            return throwError(() => error);
        })
    );
};

function getSuccessMessage(req: any, event: HttpResponse<any>): string | null {
    const url = req.url;
    const method = req.method;
    const status = event.status;

    // Специфичные сообщения для конкретных URL
    if (url.includes('/sign-up') && status === 201) {
        return 'Регистрация успешна';
    }
    if (url.includes('/update-in') && status === 200) {
        return 'Пароль обновлен';
    }
    if (url.includes('/sign-in') && status === 200) {
        return 'Вход выполнен';
    }

    // Типовые сообщения
    switch (method) {
        case 'POST':
            return status === 201 ? 'Успешно создано' : 'Успешно добавлено';
        case 'PUT':
        case 'PATCH':
            return 'Успешно обновлено';
        case 'DELETE':
            return 'Успешно удалено';
        default:
            return null;
    }
}

function getErrorMessage(error: HttpErrorResponse): string {
    const url = error.url || '';
    const status = error.status;

    // Специфичные ошибки для конкретных URL
    if (url.includes('/api/v1/sniffer/create') && status >= 500) {
        return 'Ошибка добавления сниффера';
    }

    // Ошибка от сервера или стандартная
    return error.error?.message || 'Произошла ошибка';
}