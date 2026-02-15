import { Injectable, signal } from '@angular/core';
import { jwtDecode, JwtPayload } from 'jwt-decode';

interface CustomJwtPayload extends JwtPayload {
    role?: string;
    updated?: boolean;
    username?: string;
    fullName?: string;
    sub?: string;
}

export interface UserData {
    isLogin: boolean;
    isAdmin: boolean;
    isUpdated: boolean;
    username: string;
    fullName: string;
}

@Injectable({
    providedIn: 'root',
})
export class LoginService {
    private user = signal<UserData>({
        isLogin: false,
        isAdmin: false,
        isUpdated: false,
        username: '',
        fullName: ''
    });

    readonly userData = this.user.asReadonly();

    constructor() {
        this.updateUserData();
    }

    updateUserData(): void {
        const token = localStorage.getItem('Authorization');

        if (!token) {
            this.user.set({
                isLogin: false,
                isAdmin: false,
                isUpdated: false,
                username: '',
                fullName: ''
            });
            return;
        }

        const tokenWithoutBearer = token.replace('Bearer ', '');
        const tokenInfo = this.getDecodedAccessToken(tokenWithoutBearer);

        if (!tokenInfo) {
            this.clearUserData();
            return;
        }

        // Проверка срока действия
        if (tokenInfo.exp && tokenInfo.exp < new Date().getTime() / 1000) {
            localStorage.removeItem('Authorization');
            this.clearUserData();
            return;
        }

        this.user.set({
            isLogin: true,
            isAdmin: tokenInfo.role === 'ROLE_ADMIN' ||
                (typeof tokenInfo.role === 'string' && tokenInfo.role.includes('ROLE_ADMIN')),
            isUpdated: tokenInfo.updated || false,
            username: tokenInfo.username || tokenInfo.sub || '',
            fullName: tokenInfo.fullName || ''
        });
    }

    logout(): void {
        localStorage.removeItem('Authorization');
        this.clearUserData();
    }

    private clearUserData(): void {
        this.user.set({
            isLogin: false,
            isAdmin: false,
            isUpdated: false,
            username: '',
            fullName: ''
        });
    }

    private getDecodedAccessToken(token: string): CustomJwtPayload | null {
        try {
            return jwtDecode<CustomJwtPayload>(token);
        } catch {
            return null;
        }
    }
}