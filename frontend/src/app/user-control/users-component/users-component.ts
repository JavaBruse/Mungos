import { Component, effect, inject, signal } from '@angular/core';
import { ReactiveFormsModule, Validators, FormGroup, FormControl } from '@angular/forms';
import { Router } from '@angular/router';
import { lastValueFrom } from 'rxjs';
import { HttpService } from '../../services/http.service';
import { ErrorMessageService } from '../../services/error-message.service';
import { LoginService } from '../../services/login.service';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatBadgeModule } from '@angular/material/badge';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatMenuModule } from '@angular/material/menu';
import { MatChipsModule } from '@angular/material/chips';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { UserResponseDTO } from '../../user-control/service/user-response.DTO';
import { UserService } from '../../user-control/service/user.service';
import { UserAddComponent } from "../user-add-component/user-add-component";
import { UserEditComponent } from "../user-edit-component/user-edit-component";
import { DialogComponent } from '../../dialog/dialog.component';
import { MatDialog } from '@angular/material/dialog';


@Component({
  selector: 'app-users-component',
  imports: [
    ReactiveFormsModule,
    MatCardModule,
    MatChipsModule,
    MatIconModule,
    MatInputModule,
    MatFormFieldModule,
    MatBadgeModule,
    MatButtonToggleModule,
    MatMenuModule,
    MatSelectModule,
    MatButtonModule,
    MatCheckboxModule,
    UserAddComponent,
    UserEditComponent
  ],
  templateUrl: './users-component.html',
  styleUrl: './users-component.scss',
})
export class UsersComponent {
  http = inject(HttpService);
  loginService = inject(LoginService);
  userService = inject(UserService);
  errorMessageService = inject(ErrorMessageService);
  users = this.userService.users;
  editUserId = signal<string | "">("");
  readonly dialog = inject(MatDialog);

  constructor() {
    this.userService.loadAll();
    this.userService.loadRoles();
  }

  startEdit(user: any) {
    this.editUserId.set(user.id);
  }

  finishEdit() {
    this.editUserId.set('');
    this.userService.loadAll();
  }

  delete(id: string) {
    this.userService.delete(id);
  }

  blockUser(id: string) {
  }

  openDialog(enterAnimationDuration: string, exitAnimationDuration: string, id: string): void {
    this.userService.dialogTitle = "Удаление";
    this.userService.dialogDisk = "Действие не обратимо, Вы уверены?";
    const dialogRef = this.dialog.open(DialogComponent, {
      width: '250px',
      enterAnimationDuration,
      exitAnimationDuration,
    });
    dialogRef.afterClosed().subscribe(result => {
      if (result === true) {
        this.delete(id);
      }
    });
  }

}

