import {HttpClient, HttpHeaders, HttpResponse} from "@angular/common/http";
import {Injectable} from "@angular/core";
import {Observable} from "rxjs/Rx";
import {catchError} from "rxjs/internal/operators";
import {Helper} from "../../Helper";

const endpoint = '/auth';

@Injectable()
export class ConfirmEmailService {

  httpOptions = {};

  constructor(private http: HttpClient) {
    this.httpOptions['headers'] = new HttpHeaders().set('Content-Type',  'application/json');
    this.httpOptions['observe'] = 'response';
  }


  confirmEmail(key: string): Observable<HttpResponse<any>> {

    return this.http.get<any>(endpoint + '/confirm-email/' + key, this.httpOptions)
      .pipe(
        catchError(Helper.handleError('confirmEmail', null))
      );
  }

  sendConfirmationMail(email: string): Observable<HttpResponse<any>> {
    let body = {};
    body[email] = email;
    return this.http.post<any>(endpoint + '/confirm-email', body, this.httpOptions)
      .pipe(
        catchError(Helper.handleError('confirmEmail', null))
      );

  }
}
