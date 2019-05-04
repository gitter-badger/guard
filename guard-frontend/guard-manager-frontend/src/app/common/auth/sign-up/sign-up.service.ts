import {HttpClient, HttpHeaders, HttpResponse} from "@angular/common/http";
import {Injectable} from "@angular/core";
import {Observable} from "rxjs/Rx";
import {catchError} from "rxjs/internal/operators";
import {Helper} from "../../Helper";

const endpoint = '/auth';

@Injectable()
export class SignUpService {

  constructor(private http: HttpClient) { }


  getSecurityQuestions(): Observable<any> {
    return this.http.get<any>(endpoint + '/security-questions')
      .pipe(
        catchError(Helper.handleError('getSecurityQuestions', [{"PRIMARY_SCHOOL":"What was the name of your elementary / primary school?"},{"HOSPITAL":"What's the name of the hospital in which you were born?"},{"PET":"What's the name of your first pet?"},{"NEAREST_SIBLING":"In what city or town does your nearest sibling live?"},{"CHILDHOOD_FRIEND":"What is your childhood best friend's first name?"}]))
      );
  }

  signUpUser(user: any): Observable<HttpResponse<any>> {
    let httpOptions = {};
    httpOptions['headers'] = new HttpHeaders().set('Content-Type',  'application/json');
    httpOptions['observe'] = 'response';
    return this.http.post<any>(endpoint + '/sign-up', user, httpOptions)
      .pipe(
        catchError(Helper.handleError('signUpUser', null))
      );
  }
}
