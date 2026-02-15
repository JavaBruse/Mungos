import { CanActivateChildFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { LoginService } from './services/login.service';

export const AuthGuard: CanActivateChildFn = async () => {
  const router = inject(Router);
  const loginService = inject(LoginService);
  loginService.updateUserData();
  return loginService.userData().isLogin ? true : router.createUrlTree(['/login']);
};

export const LoginGuard: CanActivateChildFn = async () => {
  const router = inject(Router);
  const loginService = inject(LoginService);
  loginService.updateUserData();
  return loginService.userData().isLogin ? router.createUrlTree(['/home']) : true;
};
