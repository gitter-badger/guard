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
import {ResetPasswordComponent} from "./reset-password/reset-password.component";
import {ResetPasswordService} from "./reset-password/reset-password.service";
import {TranslateModule} from "../../shared/i18n/translate.module";

@NgModule({
  imports: [
    RouterModule.forChild(AuthenticationRoutes),
    ArchwizardModule,
    FormsModule,
    CommonModule,
    PasswordStrengthMeterModule,
    TranslateModule
  ],
  exports: [
    FormsModule
  ],
  declarations: [
    SignInComponent,
    SignUpComponent,
    ConfirmEmailComponent,
    ResetPasswordComponent
  ],
  providers: [
    SignInService,
    SignUpService,
    ConfirmEmailService,
    ResetPasswordService
  ]
})
export class AuthenticationModule { }
