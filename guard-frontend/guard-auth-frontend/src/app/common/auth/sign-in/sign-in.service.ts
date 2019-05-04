import {HttpClient, HttpHeaders, HttpResponse} from "@angular/common/http";
import {Injectable} from "@angular/core";
import {Observable} from "rxjs/Rx";
import {catchError} from "rxjs/internal/operators";
import {Helper} from "../../Helper";

const endpoint = '/auth';

@Injectable()
export class SignInService {

  constructor(private http: HttpClient) { }



  signIn(user: any): Observable<HttpResponse<any>> {
    let httpOptions = {};
    httpOptions['headers'] = new HttpHeaders().set('Content-Type',  'application/json');
    httpOptions['observe'] = 'response';
    httpOptions['withCredentials'] = true;
    return this.http.post<any>(endpoint + '/sign-in', user, httpOptions)
      .pipe(
        catchError(Helper.handleError('signIn', null))
      );
  }

  sendPasswordResetLink(email: string): Observable<HttpResponse<any>> {
    let httpOptions = {};
    httpOptions['headers'] = new HttpHeaders().set('Content-Type',  'application/json');
    httpOptions['observe'] = 'response';
    let body = {};
    body['email'] = email;
    return this.http.post<any>(endpoint + '/reset-password', body, httpOptions)
      .pipe(
        catchError(Helper.handleError('sendPasswordResetLink', null))
      );
  }

  getRedirectUrl(id: string, url: URL): Observable<HttpResponse<any>> {
    let httpOptions = {};
    httpOptions['headers'] = new HttpHeaders().set('Content-Type',  'application/json');
    httpOptions['observe'] = 'response';
    let path = '/redirect-url';
    if (url.search !== "") {
      path = path + url.search + '&adapter_id=' + id + '&original_url=' + encodeURIComponent(url.toString());
    }
    else {
      path = path + '?adapter_id=' + id + '&original_url=' + encodeURIComponent(url.toString());
    }
    return this.http.get<any>(endpoint + path, httpOptions)
      .pipe(
        catchError(Helper.handleError('getRedirectUrl', null))
      );
  }
}
