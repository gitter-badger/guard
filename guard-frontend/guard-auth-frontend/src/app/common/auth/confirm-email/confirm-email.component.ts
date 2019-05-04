import {Component, OnInit} from '@angular/core';
import swal from 'sweetalert2'
import {ActivatedRoute, Router} from "@angular/router";
import {ConfirmEmailService} from "./confirm-email.service";
import {TranslateService} from "../../../shared/i18n/translate.service";

@Component({
  templateUrl: 'confirm-email.html'
})

export class ConfirmEmailComponent implements OnInit {

  key: string;
  email: string;

  constructor(private service: ConfirmEmailService, private router: Router, private route: ActivatedRoute, private translate: TranslateService) {
  }

  ngOnInit(): void {
    this.route.params.subscribe(params => {
      this.key = params['key'];
      this.service.confirmEmail(this.key).subscribe((result: any) => {
        if (200 === result.status) {
          swal({
              title: this.translate.data.confirm_email_success_title,
              text: this.translate.data.confirm_email_success_text,
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
              title: this.translate.data.confirm_email_warning_title,
              text: this.translate.data.confirm_email_warning_text,
              type: "warning",
              confirmButtonColor: "#ffcc00",
              confirmButtonText: this.translate.data.new_confirmation_link_text,
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
                this.service.sendConfirmationMail(resp.value).subscribe((result: any) => {
                  if (200 === result.status) {
                    swal({
                        title: this.translate.data.guard_account_creation_success,
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
      });
    });
  }

}
