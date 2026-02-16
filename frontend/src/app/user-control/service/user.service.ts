import { Injectable, inject, signal } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpService } from '../../services/http.service';
import { UserResponseDTO } from './user-response.DTO';
import { UserRequestDTO } from './user-request.DTO';

@Injectable({
    providedIn: 'root',
})
export class UserService {
    private http = inject(HttpService);
    private url = environment.apiUrl;
    private apiUrl = this.url + 'api/v1/users-control';
    dialogTitle: string | null = null;
    dialogDisk: string | null = null;
    private readonly usersSignal = signal<UserResponseDTO[]>([]);
    private readonly rolesSignal = signal<string[]>([]); // для хранения ролей
    private readonly visibleAddUserSignal = signal(false);
    private readonly visibleEditUserSignal = signal(false);

    readonly users = this.usersSignal.asReadonly();
    readonly roles = this.rolesSignal.asReadonly();
    readonly visibleAdd = this.visibleAddUserSignal.asReadonly();
    readonly visibleEdit = this.visibleEditUserSignal.asReadonly();

    loadAll() {
        this.http.get<UserResponseDTO[]>(`${this.apiUrl}/users`).subscribe({
            next: (users) => this.usersSignal.set(users),
            error: () => this.usersSignal.set([]),
        });
    }

    loadRoles() {
        this.http.get<string[]>(`${this.apiUrl}/roles`).subscribe({
            next: (roles) => this.rolesSignal.set(roles),
            error: () => { this.rolesSignal.set([]); }
        });
    }

    add(userData: UserRequestDTO) {
        this.http.post<any>(`${this.apiUrl}/create`, userData).subscribe({
            next: (response) => { this.loadAll(); },
            error: () => this.usersSignal.set([]),
        });
    }

    changePassword(id: string) {
        this.http.put<string>(`${this.apiUrl}/change-password/${id}`, {}).subscribe({
            next: () => { this.loadAll(); },
            error: () => this.usersSignal.set([]),
        });
    }

    delete(id: string) {
        this.http.delete<void>(`${this.apiUrl}/delete/${id}`).subscribe({
            next: () => { this.loadAll(); },
            error: () => this.usersSignal.set([]),
        });
    }

    setVisibleAdd(value: boolean) {
        this.visibleAddUserSignal.set(value);
    }

    setVisibleEdit(value: boolean) {
        this.visibleEditUserSignal.set(value);
    }

    clear() {
        this.usersSignal.set([]);
        this.visibleAddUserSignal.set(false);
        this.visibleEditUserSignal.set(false);
    }
}