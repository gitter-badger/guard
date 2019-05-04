import { NgModule } from '@angular/core';
import { Routes } from '@angular/router';

//Authentication Components
import { SignInComponent } from './sign-in/sign-in.component';
import { SignUpComponent } from './sign-up/sign-up.component';
import {ConfirmEmailComponent} from "./confirm-email/confirm-email.component";


export const AuthenticationRoutes: Routes = [
  {
    path: '',
    children: [
      {
        path: 'sign-in',
        component: SignInComponent,
      },
      {
        path: 'sign-up',
        component: SignUpComponent,
      },
      {
        path: 'confirm-email/:key',
        component: ConfirmEmailComponent,
      },
    ]
  },
  {
    path: '**',
    redirectTo: 'sign-in',
    pathMatch: 'full',
  }
];

