import { effect, Injectable, signal } from '@angular/core';


@Injectable({
    providedIn: 'root',
})
export class StyleSwitcherService {
    public isLightThem: 'light' | 'dark' | any;
    private isLightThemeSignal = signal<boolean>(true);
    private isMobileView = signal<boolean>(false);
    constructor() {
        const savedTheme = (localStorage.getItem('theme') as 'light' | 'dark') || 'light';
        this.setTheme(savedTheme);
        effect((onCleanup) => {
            const checkSize = () => {
                this.isMobileView.set(window.innerWidth <= 768);
            };
            checkSize();
            window.addEventListener('resize', checkSize);
            onCleanup(() => {
                window.removeEventListener('resize', checkSize);
            });
        });
    }

    get themeSignal() {
        return this.isLightThemeSignal();
    }

    get isMobileViewSignal() {
        return this.isMobileView.asReadonly();
    }

    switchTheme(theme: 'light' | 'dark') {
        this.setTheme(theme);
        localStorage.setItem('theme', theme);
        document.body.setAttribute('data-theme', theme);
    }

    private setTheme(theme: 'light' | 'dark') {
        const isLight = theme === 'light';
        this.isLightThemeSignal.set(isLight);
    }
}
