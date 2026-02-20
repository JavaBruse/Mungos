import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './login/login.component';
import { RootComponent } from './services/root.service';
import { AuthGuard, LoginGuard } from './auth.guard';
import { HomeComponent } from './home/home.component';
import { FirstLoginPassword } from './first-login-password/first-login-password';
import { UsersComponent } from './user-control/users-component/users-component';
import { SniffersComponent } from './sniffer-control/sniffers-component/sniffers-component';
import { SnifferWebsocketComponent } from './sniffer-control/sniffer-websocket-component/sniffer-websocket-component';

export const routes: Routes = [
    { path: '', component: RootComponent, pathMatch: 'full' },
    { path: 'login', component: LoginComponent, canActivate: [LoginGuard] },
    { path: 'home', component: HomeComponent, canActivate: [AuthGuard] },
    { path: 'settings/users', component: UsersComponent, canActivate: [AuthGuard] },
    { path: 'settings/sniffers', component: SniffersComponent, canActivate: [AuthGuard] },
    { path: 'sniffers', component: SniffersComponent, canActivate: [AuthGuard] },
    { path: 'sniffer/:id', component: SnifferWebsocketComponent, canActivate: [AuthGuard] },
    { path: 'update-password', component: FirstLoginPassword, canActivate: [AuthGuard] },
    { path: 'admin/monitoring/**', redirectTo: '' },
    { path: '**', redirectTo: '', pathMatch: 'full' }
];

@NgModule({
    imports: [RouterModule.forRoot(routes)],
    exports: [RouterModule],
})
export class AppRoutingModule { }
