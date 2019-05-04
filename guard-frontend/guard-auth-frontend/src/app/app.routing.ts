import { Routes} from '@angular/router';
import {ConsentComponent} from "./consent/consent.component";


export const AppRoutes: Routes = [

  {
    path: '',
    redirectTo: 'auth/',
    pathMatch: 'full',
  },
  {
    path: '',
    children: [
      {
        path: 'auth',
        loadChildren: './common/auth/authentication.modules#AuthenticationModule'
      }
    ]
  },
  {
    path: 'consent',
    component: ConsentComponent,
  },
  {
    path: '**',
    redirectTo: 'auth/',
    pathMatch: 'full',
  },
];

