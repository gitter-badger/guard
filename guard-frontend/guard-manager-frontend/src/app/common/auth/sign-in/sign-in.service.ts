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
    return this.http.post<any>(endpoint + '/sign-in', user, httpOptions)
      .pipe(
        catchError(Helper.handleError('signIn', null))
      );
  }
}
