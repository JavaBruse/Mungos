import { Injectable, signal } from '@angular/core';
import { jwtDecode, JwtPayload } from 'jwt-decode';

interface CustomJwtPayload extends JwtPayload {
    role?: string;
    roles?: string[];
    // добавьте другие кастомные поля если нужно
}
@Injectable({
    providedIn: 'root',
})
export class CheckToken {
    token: string | null = null;
    isAdmin = signal<boolean>(false);

    get isAdminSignal() {
        return this.isAdmin;
    }

    async validateToken(): Promise<boolean> {
        this.token = localStorage.getItem('Authorization');
        if (this.token === null) {
            return false;
        }
        const tokenInfo = this.getDecodedAccessToken(this.token);
        if (tokenInfo === null) {
            return false;
        }
        const expireDate = tokenInfo.exp;
        if (expireDate < new Date().getTime() / 1000) {
            localStorage.removeItem('Authorization');
            return false;
        }
        return true;
    }

    getDecodedAccessToken(token: string): any {
        try {
            return jwtDecode(token);
        } catch (Error) {
            return null
        }
    }

    checkAdminRole(): void {
        this.token = localStorage.getItem('Authorization');
        if (!this.token) {
            this.isAdmin.set(false);
            return;
        }
        try {
            const tokenInfo = jwtDecode<CustomJwtPayload>(this.token);
            const hasAdminRole =
                tokenInfo.role === 'ROLE_ADMIN' ||
                (Array.isArray(tokenInfo.roles) && tokenInfo.roles.includes('ROLE_ADMIN')) ||
                (typeof tokenInfo.role === 'string' && tokenInfo.role.includes('ROLE_ADMIN'));

            this.isAdmin.set(hasAdminRole);
        } catch (error) {
            this.isAdmin.set(false);
        }
    }

    updateAdminStatus(): void {
        this.checkAdminRole();
    }

    clearAdminStatus(): void {
        this.isAdmin.set(false);
    }
}

