import { CanActivateChildFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { CheckToken } from './services/checkToken.service';
import { LoginService } from './services/login.service';

export const AuthGuard: CanActivateChildFn = async (childRoute, state) => {
  const router = inject(Router);
  const loginService = inject(LoginService);
  const checkToken = inject(CheckToken);
  const isValidTocken = await checkToken.validateToken();
  loginService.setIsLoginSignal(isValidTocken);
  return isValidTocken ? true : router.createUrlTree(['/login']);
};

export const LoginGuard: CanActivateChildFn = async (childRoute, state) => {
  const router = inject(Router);
  const loginService = inject(LoginService);
  const checkToken = inject(CheckToken);
  const isValidTocken = await checkToken.validateToken();
  loginService.setIsLoginSignal(isValidTocken);
  return isValidTocken ? router.createUrlTree(['/home']) : true;
};