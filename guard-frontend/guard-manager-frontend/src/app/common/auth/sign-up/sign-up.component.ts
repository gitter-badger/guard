import {Component, ElementRef, OnInit, ViewEncapsulation} from '@angular/core';
import {SignUpService} from "./sign-up.service";
import swal from 'sweetalert2'
import {Router} from "@angular/router";

@Component ({
  templateUrl: 'sign-up.html',
  encapsulation: ViewEncapsulation.None,
})

export class SignUpComponent implements OnInit {

  constructor(private service: SignUpService, private router: Router) { }


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
            title: "Perfect " + this.user.givenName + " !",
            text: "Check your mail box (" + this.user.email + ") for further instructions",
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
            title: "Zut!!! " + this.user.givenName + " !",
            text: "It seems like your email already exist in our system. Maybe you should try to reset your password",
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
            title: "Zut!!! " + this.user.givenName + " !",
            text: "We were unable to create your account. Please check your input and try again",
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
