import {Component, OnInit} from '@angular/core';
import {ActivatedRoute, Router} from "@angular/router";
import {SignInService} from "./sign-in.service";
import swal from "sweetalert2";
import {AppService} from "../../../app.service";
import {TranslateService} from "../../../shared/i18n/translate.service";

@Component({
  templateUrl: 'sign-in.html'
})

export class SignInComponent implements OnInit {


  user: any = {};
  context: any = {};
  GUARD_ORIGINAL_URL_CONFIG_KEY = "guard_original_url";
  originalUrl: string = null;

  constructor(private service: SignInService, private appService: AppService, private router: Router, private route: ActivatedRoute, private translate: TranslateService) {}

  ngOnInit(): void {
    this.appService.getContext().subscribe((result: any) => {
      this.context = result;
    });
    this.route.queryParams.subscribe(params => {
      this.originalUrl = params['original_url'];
    });
  }

  redirectToAdapter(id: string): void {
    let url = this.originalUrl;
    if (url === undefined || url === null) {
      if (localStorage.getItem(this.GUARD_ORIGINAL_URL_CONFIG_KEY) != null) {
        url = localStorage.getItem(this.GUARD_ORIGINAL_URL_CONFIG_KEY);
      }
      else {
        url = location.protocol + "//" + location.host + "/manager";
      }
    }
    this.service.getRedirectUrl(id, new URL(url)).subscribe((result: any) => {
      location.replace(result.body.url);
    });
  }

  signIn(): void {
    this.service.signIn(this.user).subscribe((result: any) => {
      if (200 === result.status) {
        if (this.originalUrl != null) {
          location.replace(this.originalUrl);
        }
        else if (localStorage.getItem(this.GUARD_ORIGINAL_URL_CONFIG_KEY) != null) {
          location.replace(localStorage.getItem(this.GUARD_ORIGINAL_URL_CONFIG_KEY))
        }
        else {
          location.replace(location.protocol + "//" + location.host + "/manager");
        }
        localStorage.removeItem(this.GUARD_ORIGINAL_URL_CONFIG_KEY);
      }
      else {
        swal({
            title: this.translate.data.signin_warning_title,
            text: this.translate.data.signin_warning_text,
            type: "warning",
            confirmButtonColor: "#f9b42c",
            allowEscapeKey: false,
            allowOutsideClick: false
          }
        );
      }
    });
  }

  signUp(): void {
    if (this.originalUrl != null) {
      localStorage.setItem(this.GUARD_ORIGINAL_URL_CONFIG_KEY, this.originalUrl);
    }
  }

  requestPasswordResetLink(): void {
    if (this.originalUrl != null) {
      localStorage.setItem(this.GUARD_ORIGINAL_URL_CONFIG_KEY, this.originalUrl);
    }
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
              text: this.translate.data.check_mail_box,
              type: "success",
              confirmButtonColor: "#37c936",
              allowEscapeKey: false,
              allowOutsideClick: false
            }
          );
        }
        else {
          swal({
              text: this.translate.data.reset_password_failed_try_again_text,
              type: "warning",
              confirmButtonColor: "#ffcc00",
              allowEscapeKey: false,
              allowOutsideClick: false,
            }
          )
        }
      })
    });
  }
}
