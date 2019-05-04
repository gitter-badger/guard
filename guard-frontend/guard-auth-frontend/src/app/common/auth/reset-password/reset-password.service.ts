import {HttpClient, HttpHeaders, HttpResponse} from "@angular/common/http";
import {Injectable} from "@angular/core";
import {Observable} from "rxjs/Rx";
import {catchError} from "rxjs/internal/operators";
import {Helper} from "../../Helper";

const endpoint = '/auth';

@Injectable()
export class ResetPasswordService {

  constructor(private http: HttpClient) { }


  getSecurityQuestions(key: string): Observable<HttpResponse<any>> {
    let httpOptions = {};
    httpOptions['headers'] = new HttpHeaders().set('Content-Type',  'application/json');
    httpOptions['observe'] = 'response';
    return this.http.get<any>(endpoint + '/reset-password/' + key)
      .pipe(
        catchError(Helper.handleError('getSecurityQuestions', null))
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

  resetPassword(user: any, key: string): Observable<HttpResponse<any>> {
    let httpOptions = {};
    httpOptions['headers'] = new HttpHeaders().set('Content-Type',  'application/json');
    httpOptions['observe'] = 'response';
    return this.http.post<any>(endpoint + '/reset-password/' + key, user, httpOptions)
      .pipe(
        catchError(Helper.handleError('signUpUser', null))
      );
  }
}
