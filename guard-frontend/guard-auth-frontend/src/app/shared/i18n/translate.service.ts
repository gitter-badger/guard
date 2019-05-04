import { Injectable } from '@angular/core';
import {HttpClient} from "@angular/common/http";

@Injectable({
  providedIn: 'root'
})
export class TranslateService {

  data: any = {};

  constructor(private http: HttpClient) { }

  use(lang: string): Promise<{}> {
    return new Promise<{}>((resolve, reject) => {
      let locale = lang.substr(0, 2);
      let langPath;
      if (locale === 'fr') {
        langPath = `assets/i18n/fr.json`;
      } else {
        langPath = `assets/i18n/en.json`;
      }
      this.http.get<{}>(langPath).subscribe(
        translation => {
          this.data = Object.assign({}, translation || {});
          resolve(this.data);
        },
        error => {
          this.data = {};
          resolve(this.data);
        }
      );
    });
  }
}
