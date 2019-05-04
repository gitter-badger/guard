import { Routes} from '@angular/router';

import { CommonLayoutComponent } from './common/common-layout.component';
import { AuthenticationLayoutComponent } from './common/auth/authentication-layout.component';

export const AppRoutes: Routes = [

  {
    path: '',
    redirectTo: 'auth/',
    pathMatch: 'full',
  },
  {
    path: '',
    component: AuthenticationLayoutComponent,
    children: [
      {
        path: 'auth',
        loadChildren: './common/auth/authentication.modules#AuthenticationModule'
      }
    ]
  },
  {
    path: 'consent',
    component: CommonLayoutComponent,
  },
  {
    path: '**',
    redirectTo: 'auth/',
    pathMatch: 'full',
  },
];

