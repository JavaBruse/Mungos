import { inject, Injectable, signal } from '@angular/core';
import { Router } from '@angular/router';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { ErrorMessageService } from '../services/error-message.service';
import { lastValueFrom } from 'rxjs';
import { environment } from '../../environments/environment';
import { jwtDecode, JwtPayload } from 'jwt-decode';
import { CheckToken } from './checkToken.service';

interface CustomJwtPayload extends JwtPayload {
    role?: string;
    roles?: string[];
}
@Injectable({
    providedIn: 'root',
})
export class LoginService {
    private isLogin = signal<boolean>(false);
    private checkToken = inject(CheckToken);


    private initService = signal<boolean>(false);
    private tokenAccessSignal = signal('');
    private router = inject(Router);
    private httpClient = inject(HttpClient);
    private errorMessageService = inject(ErrorMessageService);
    private isAdmin = signal<boolean>(false);
    private url = environment.apiUrl;
    private urls = this.url + 'security/auth/';

    constructor() {
        this.initializeLoginStatus();
    }


    private async initializeLoginStatus() {
        const isValid = await this.checkToken.validateToken();
        this.setIsLoginSignal(isValid);
    }

    get isLoginSignal() {
        return this.isLogin;
    }

    setIsLoginSignal(signal: boolean) {
        this.isLogin.set(signal);
    }

    get isAdminSignal() {
        return this.isAdmin;
    }

    get isInitService() {
        return this.initService;
    }

    setInitService(signal: boolean) {
        this.isInitService.set(signal);
    }

    get tokenAccess() {
        return this.tokenAccessSignal;
    }

    private setToken(token: string) {
        this.tokenAccessSignal.set(token);
    }


    async authTokens(url: string, authData: any) {
        try {
            const response: any = await lastValueFrom(
                this.httpClient.post(url, authData, {
                    headers: new HttpHeaders({ 'Content-Type': 'application/json' }),
                    withCredentials: true,
                })
            );
            this.setToken(response.accessToken);
            this.setIsLoginSignal(true);
            this.router.navigate(['home']);
        } catch (error) {
            this.errorMessageService.showError('"Отказано в доступе"' + error);
        }
    }

    async logout() {
        try {
            await lastValueFrom(
                this.httpClient.put(this.urls + 'logout', {}, { withCredentials: true })
            );
        } catch (error) {
            this.errorMessageService.showError('"Ошибка при logout"' + error);
        } finally {
            this.tokenAccessSignal.set('');
            this.isLoginSignal.set(false);
            this.router.navigate(['login']);
        }
    }

    async validateToken(): Promise<boolean> {
        const token = this.tokenAccessSignal();
        if (!token) return false;

        const decoded = this.getDecodedToken();
        if (!decoded) return false;

        const isExpired = decoded.exp * 1000 < Date.now();
        return !isExpired;
    }

    private clearToken() {
        this.tokenAccessSignal.set('');
        this.setIsLoginSignal(false);
    }

    getDecodedToken(): any {
        try {
            return jwtDecode(this.tokenAccessSignal());
        } catch (Error) {
            return null
        }
    }

    checkAdminRole(token: string): void {
        if (!token) {
            this.isAdmin.set(false);
            return;
        }
        try {
            const tokenInfo = jwtDecode<CustomJwtPayload>(token);
            const hasAdminRole =
                tokenInfo.role === 'ROLE_ADMIN' ||
                (Array.isArray(tokenInfo.roles) && tokenInfo.roles.includes('ROLE_ADMIN')) ||
                (typeof tokenInfo.role === 'string' && tokenInfo.role.includes('ROLE_ADMIN'));
            this.isAdmin.set(hasAdminRole);
        } catch (error) {
            this.isAdmin.set(false);
        }
    }


    hasRole(role: string): boolean {
        const decoded = this.getDecodedToken();
        if (!decoded) return false;
        if (decoded.role === role) return true;
        if (Array.isArray(decoded.roles) && decoded.roles.includes(role)) return true;
        return false;
    }
}

