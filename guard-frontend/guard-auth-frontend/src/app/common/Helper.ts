import {Observable} from "rxjs/Rx";
import {of} from "rxjs/index";

export class Helper {
  /**
   * Handle Http operation that failed.
   * Let the app continue.
   * @param operation - name of the operation that failed
   * @param result - optional value to return as the observable result
   */
  public static handleError<T>(operation: string, result: T) {
    function handle(error: any, result: T):  Observable<T> {
      console.error("Error on " + operation + ": <" + error.statusText + "> : " + JSON.stringify(error.error));
      if (result != null) {
        return of(result);
      }
      else {
        return of(error);
      }
    }

    return (error: any): Observable<T> => {
      if (401 === error.status) {
        if (!location.href.includes("/#/auth")) {
          location.replace(location.protocol + "//" + location.host + "/#/auth/sign-in?original_url=" + encodeURIComponent(location.href));
          return of();
        }
        else {
         return handle(error, result);
        }
      }
      else {
       return handle(error, result);
      }
    };
  }
}
