import {Component, OnInit} from '@angular/core';
import {ActivatedRoute, Router} from "@angular/router";
import {ConsentService} from "./consent.service";
import swal from "sweetalert2";
import {TranslateService} from "../shared/i18n/translate.service";

@Component({
  templateUrl: 'consent.html'
})

export class ConsentComponent implements OnInit {

  consents: any[] = [];
  scopes: any[] = [];
  consented: any[] = [];
  toBeConsented: any[] = [];
  mfaRequired: any[] = [];
  originalUrl: string;
  redirectUri: string;
  client: any = {};
  clientId: string;

  constructor(private service: ConsentService, private router: Router, private route: ActivatedRoute, private translate: TranslateService) {
  }

  getLocaleScopeDescription(scope: any): string {
    if ('fr' === window.navigator.language.substr(0, 2) && scope.frDescription !== null) {
      return scope.frDescription;
    }
    else {
      return scope.enDescription;
    }
  }

  ngOnInit(): void {
    this.route.queryParamMap.subscribe(paramsMap => {
      this.consented = paramsMap.getAll('consented');
      this.toBeConsented = paramsMap.getAll('to_be_consented');
      this.mfaRequired = paramsMap.getAll('mfa_required');
      this.originalUrl = paramsMap.get('original_url');
      this.redirectUri = paramsMap.get('redirect_uri');
      this.clientId = paramsMap.get('client_id');

      let qs = "name=";
      qs = qs + this.toBeConsented[0];
      for (let i = 1; i <= this.toBeConsented.length - 1; i++) {
        qs = qs + "&name=" + this.toBeConsented[i];
      }
      this.consented.forEach((scope: string) => {
        qs = qs + "&name=" + scope;
      });

      this.service.getClient(this.clientId).subscribe((result) => {
        if (result) {
          this.client = result.body;
          this.service.getScopes(qs).subscribe((result: any) => {
            this.scopes = result.body;
            this.scopes.forEach((s: any) => {
              s['consented'] = true;
            });
            document.getElementById("openModal").click();
          });
        }
        else {
          location.replace(this.redirectUri + "#error=invalid_request");
        }
      });
    });
  }

  submit(): any {
    this.scopes.forEach((scope: any) => {
      let consent = {};
      if (this.toBeConsented.includes(scope.name) && scope.consented) {
        consent['scopeName'] = scope.name;
        consent['clientId'] = this.client.id;
        consent['clientName'] = this.client.name;
        this.consents.push(consent);
      }
    });

    if (this.consents.length === 0) {
      swal({
          title: this.translate.data.consent_warning,
          text: this.translate.data.not_consent_to_scope + this.client.name + this.translate.data.redirect_to_requester_app,
          type: "warning",
          confirmButtonColor: "#f9b42c",
          allowEscapeKey: false,
          allowOutsideClick: false,
          onAfterClose: () => {
            location.replace(this.redirectUri + "#error=access_denied");
          }
        }
      );
    }
    else {
      this.service.postConsent(this.consents).subscribe((result: any) => {
        if (201 !== result.status) {
          swal({
              title: this.translate.data.consent_warning,
              text: this.translate.data.try_again_later,
              type: "warning",
              confirmButtonColor: "#f9b42c",
              allowEscapeKey: false,
              allowOutsideClick: false,
              onAfterClose: () => {
                location.replace(this.redirectUri + "#error=server_error");
              }
            }
          );
        }
        else {
          location.replace(this.originalUrl);
        }
      });
    }
  }

}
