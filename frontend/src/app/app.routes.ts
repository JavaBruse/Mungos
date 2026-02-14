import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './login/login.component';
import { RegistrationComponent } from './registration/registration.component';
import { RootComponent } from './services/root.service';
import { AuthGuard, LoginGuard } from './auth.guard';

export const routes: Routes = [
    // { path: '', redirectTo: 'login', canActivate: [AuthGuard] },
    { path: '', component: RootComponent, pathMatch: 'full' },
    { path: 'login', component: LoginComponent, canActivate: [LoginGuard] },
    { path: 'registration', component: RegistrationComponent, canActivate: [LoginGuard] },
    { path: 'admin/monitoring/**', redirectTo: '' },
    { path: '**', redirectTo: '', pathMatch: 'full' }
];

@NgModule({
    imports: [RouterModule.forRoot(routes)],
    exports: [RouterModule],
})
export class AppRoutingModule { }
