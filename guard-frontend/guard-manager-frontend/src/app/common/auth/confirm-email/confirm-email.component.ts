import {Component, OnInit} from '@angular/core';
import swal from 'sweetalert2'
import {ActivatedRoute, Router} from "@angular/router";
import {ConfirmEmailService} from "./confirm-email.service";
import {el} from "@angular/platform-browser/testing/src/browser_util";

@Component ({
  templateUrl: 'confirm-email.html'
})

export class ConfirmEmailComponent implements OnInit {

  constructor(private service: ConfirmEmailService, private router: Router, private route: ActivatedRoute) { }


  key: string;
  email: string;


  ngOnInit(): void {
    this.route.params.subscribe(params => {
      this.key = params['key'];
      this.service.confirmEmail(this.key).subscribe((result: any) => {
        if (200 === result.status) {
          swal({
              title: "Whaouh!!! ",
              text: "You just activated your guard account, You can sign-in now.",
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
              title: "Zut!!! ",
              text: "We were unable to confirm your account. Maybe the link is no more valid.",
              type: "warning",
              confirmButtonColor: "#ffcc00",
              confirmButtonText: "New confirmation link ?",
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
                text: 'Enter the email address your used to create your Guard account:',
                input: 'email',
                confirmButtonColor: "#f9b42c",
                confirmButtonText: "Send me a confirmation link!",
                allowEscapeKey: false,
                allowOutsideClick: false,
                focusConfirm: false,
              }).then(resp => {
                this.service.sendConfirmationMail(resp.value).subscribe((result: any) => {
                  if (200 === result.status) {
                    swal({
                        title: "Good ! ",
                        text: "Check your mail box (" + resp.value + ") for further instructions",
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
                        text: "We were unable to send you a new confirmation link! Try again later or try to create a new account.",
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
