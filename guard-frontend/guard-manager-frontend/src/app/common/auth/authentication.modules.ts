import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';


import { AuthenticationRoutes } from './authentication.routing';

//Authentication Component
import { SignInComponent } from './sign-in/sign-in.component';
import { SignUpComponent } from './sign-up/sign-up.component';
import { ArchwizardModule } from 'angular-archwizard';
import { FormsModule } from '@angular/forms';
import {PasswordStrengthMeterModule} from "angular-password-strength-meter";
import { SignUpService } from './sign-up/sign-up.service';
import {CommonModule} from "@angular/common";
import {ConfirmEmailComponent} from "./confirm-email/confirm-email.component";
import {ConfirmEmailService} from "./confirm-email/confirm-email.service";
import {SignInService} from "./sign-in/sign-in.service";

@NgModule({
  imports: [
    RouterModule.forChild(AuthenticationRoutes),
    ArchwizardModule,
    FormsModule,
    CommonModule,
    PasswordStrengthMeterModule
  ],
  exports: [
    FormsModule
  ],
  declarations: [
    SignInComponent,
    SignUpComponent,
    ConfirmEmailComponent
  ],
  providers: [
    SignInService,
    SignUpService,
    ConfirmEmailService
  ]
})
export class AuthenticationModule { }
