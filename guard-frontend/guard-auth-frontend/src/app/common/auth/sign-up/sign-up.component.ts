import {Component, ElementRef, OnInit, ViewEncapsulation} from '@angular/core';
import {SignUpService} from "./sign-up.service";
import swal from 'sweetalert2'
import {Router} from "@angular/router";
import {TranslateService} from "../../../shared/i18n/translate.service";

@Component ({
  templateUrl: 'sign-up.html',
  encapsulation: ViewEncapsulation.None,
})

export class SignUpComponent implements OnInit {

  constructor(private service: SignUpService, private router: Router, private translate: TranslateService) { }


  pwdStrength = 0;
  user : any = {};
  securityQuestions : any = [];
  secQuestion1 : any = {};
  secQuestion2 : any = {};

  ngOnInit(): void {
    this.user.securityQuestion = {};
    this.service.getSecurityQuestions().subscribe((result: any) => {
      this.securityQuestions = result;
    });
  }

  setPwdStrength($event): void {
    this.pwdStrength = $event;
  }

  getValue(q: any): string {
    return JSON.stringify(Object.values(q)[0]).replace('"', '').replace('"', '');
  }

  getKey(q: any): string {
    return JSON.stringify(Object.entries(q)[0][0]).replace('"', '').replace('"', '');
  }

  signUp(): void {
    delete this.user.confirmPwd;
    this.user.securityQuestion[this.secQuestion1.key] = this.secQuestion1.response;
    this.user.securityQuestion[this.secQuestion2.key] = this.secQuestion2.response;


    this.service.signUpUser(this.user).subscribe((result: any) => {
      if (201 === result.status) {
        swal({
            title: this.translate.data.guard_account_creation_success + ", " + this.user.givenName + " !",
            text: this.translate.data.check_your_mailbox + this.user.email + this.translate.data.for_further_instructions,
            type: "success",
            confirmButtonColor: "#37c936",
            allowEscapeKey: false,
            allowOutsideClick: false,
            onAfterClose: () => {
              this.router.navigateByUrl('/auth/sign-in')
            }
          }
        );
      }
      else if(409 === result.status) {
        swal({
            title: this.translate.data.signup_already_signedup_title,
            text: this.translate.data.signup_already_signedup_text,
            type: "warning",
            confirmButtonColor: "#f9b42c",
            allowEscapeKey: false,
            allowOutsideClick: false,
            onAfterClose: () => {
              this.router.navigateByUrl('/auth/sign-in')
            }
          }
        );
      }
      else {
        swal({
            title: this.translate.data.signup_failed_title,
            text: this.translate.data.signup_failed_text,
            type: "warning",
            confirmButtonColor: "#f9b42c",
            allowEscapeKey: false,
            allowOutsideClick: false
          }
        );
      }
    });
  }

}
