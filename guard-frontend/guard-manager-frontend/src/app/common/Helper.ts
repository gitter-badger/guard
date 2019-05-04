import {Observable} from "rxjs/Rx";
import {of} from "rxjs/index";
import {el} from "@angular/platform-browser/testing/src/browser_util";

export class Helper {
  /**
   * Handle Http operation that failed.
   * Let the app continue.
   * @param operation - name of the operation that failed
   * @param result - optional value to return as the observable result
   */
  public static handleError<T> (operation = 'operation', result?: T) {
    return (error: any): Observable<T> => {
      if (401 === error.status) {
        if (!location.href.includes("/#/auth/sign-in")) {
          location.assign(location.host + "/#/auth/sign-in?original_url=" + location.href);
        }
      }
      else {
        console.error("Error on " + operation + ": <" + error.statusText + "> : " + JSON.stringify(error.error));
        if (result != null) {
          return of(result);
        }
        else {
          return of(error);
        }
      }
    };
  }
}
