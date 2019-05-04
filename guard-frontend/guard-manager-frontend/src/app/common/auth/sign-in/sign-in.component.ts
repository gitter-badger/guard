import {Component, OnInit} from '@angular/core';
import {ActivatedRoute, Router} from "@angular/router";
import {SignInService} from "./sign-in.service";
import swal from "sweetalert2";

@Component ({
  templateUrl: 'sign-in.html'
})

export class SignInComponent implements OnInit {

  constructor(private service: SignInService, private router: Router, private route: ActivatedRoute) { }
  user : any = {};

  GUARD_ORIGINAL_URL_CONFIG_KEY = "guard_original_url";
  originalUrl: string = null;

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      this.originalUrl = params['original_url'];
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
          location.assign("/manager/");
        }
        localStorage.removeItem(this.GUARD_ORIGINAL_URL_CONFIG_KEY);
      }
      else {
        swal({
            title: "Zut!!! ",
            text: "Something went wrong. Please check your entry and try again.",
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


}
