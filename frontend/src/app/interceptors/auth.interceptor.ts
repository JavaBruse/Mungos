import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { LoginService } from '../services/login.service';

export const AuthInterceptor: HttpInterceptorFn = (req, next) => {
    const token = localStorage.getItem('Authorization');
    const authReq = token ? req.clone({ setHeaders: { Authorization: `${token}` } }) : req;
    return next(authReq);
};
