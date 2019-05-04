import {Component, OnInit} from '@angular/core';
import swal from 'sweetalert2'
import {ActivatedRoute, Router} from "@angular/router";
import {ResetPasswordService} from "./reset-password.service";
import {TranslateService} from "../../../shared/i18n/translate.service";

@Component({
  templateUrl: 'reset-password.html'
})

export class ResetPasswordComponent implements OnInit {

  pwdStrength = 0;
  user: any = {};
  securityQuestions: any = [];
  secQuestion1: any = {};
  secQuestion2: any = {};
  key: string;

  constructor(private service: ResetPasswordService, private router: Router, private route: ActivatedRoute, private translate: TranslateService) {

  }

  ngOnInit(): void {
    console.log(window.navigator.language);
    this.user.security_question = {};
    this.route.params.subscribe(params => {
      this.key = params['key'];
      this.service.getSecurityQuestions(this.key).subscribe((result: any) => {
        if (!result.status) {
          this.securityQuestions = result;
        }
        else if (403 === result.status) {
          swal({
              title: this.translate.data.reset_password_warning_title,
              text: this.translate.data.reset_password_warning_title,
              type: "warning",
              confirmButtonColor: "#ffcc00",
              confirmButtonText: this.translate.data.new_confirmation_link,
              showCancelButton: true,
              allowEscapeKey: false,
              allowOutsideClick: false,
              onAfterClose: () => {
                this.router.navigateByUrl('/auth/sign-in')
              }
            }
          ).then((resp) => {
            if (resp.value) {
              swal({
                text: this.translate.data.enter_email_for_new_confirmation_link,
                input: 'email',
                confirmButtonColor: "#f9b42c",
                confirmButtonText: this.translate.data.send_confirmation_link,
                allowEscapeKey: false,
                allowOutsideClick: false,
                focusConfirm: false,
              }).then(resp => {
                this.service.sendPasswordResetLink(resp.value).subscribe((result: any) => {
                  if (200 === result.status) {
                    swal({
                        title: this.translate.data.reset_password_link_sended,
                        text: this.translate.data.check_mail_box + "(" + resp.value + ")",
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
                  else {
                    swal({
                        text: this.translate.data.unable_to_send_confirmation_link,
                        type: "warning",
                        confirmButtonColor: "#ffcc00",
                        allowEscapeKey: false,
                        allowOutsideClick: false,
                        onAfterClose: () => {
                          this.router.navigateByUrl('/auth/sign-in')
                        }
                      }
                    )
                  }
                })
              });
            }
          });
        }
        else {
          swal({
              title: this.translate.data.reset_password_failed_title,
              text: this.translate.data.reset_password_failed_text,
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
      });
    })
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

  resetPassword(): void {
    delete this.user.confirmPwd;
    this.user.security_question[this.secQuestion1.key] = this.secQuestion1.response;
    this.user.security_question[this.secQuestion2.key] = this.secQuestion2.response;


    this.service.resetPassword(this.user, this.key).subscribe((result: any) => {
      if (200 === result.status) {
        swal({
            title: this.translate.data.reset_password_success_title,
            text: this.translate.data.reset_password_success_text,
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
      else if (403 === result.status) {
        swal({
            title: this.translate.data.reset_password_failed_title,
            text: this.translate.data.reset_password_failed_title,
            type: "warning",
            confirmButtonColor: "#f9b42c",
            allowEscapeKey: false,
            allowOutsideClick: false
          }
        );
      }
      else {
        swal({
            title: this.translate.data.reset_password_failed_title,
            text: this.translate.data.reset_password_failed_try_again_later_text,
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
    });
  }

}
