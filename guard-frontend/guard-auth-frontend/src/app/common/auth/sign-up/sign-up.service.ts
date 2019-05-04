import {HttpClient, HttpHeaders, HttpResponse} from "@angular/common/http";
import {Injectable} from "@angular/core";
import {Observable} from "rxjs/Rx";
import {catchError} from "rxjs/internal/operators";
import {Helper} from "../../Helper";

const endpoint = '/auth';

@Injectable()
export class SignUpService {

  constructor(private http: HttpClient) {
  }


  getSecurityQuestions(): Observable<any> {
    let locale = window.navigator.language.substr(0, 2);
    if (locale === 'fr') {
      return this.http.get<any>(endpoint + '/security-questions')
        .pipe(
          catchError(Helper.handleError('getSecurityQuestions',
            [{"PRIMARY_SCHOOL": "Quel est le nom de votre école maternelle / primaire ?"},
              {"HOSPITAL": "Quel est le nom de l'hôpital dans lequel vous êtes né(e) ?"},
              {"PET": "Quel est le nom de votre premier animal de compagnie ?"},
              {"NEAREST_SIBLING": "Dans quel ville habite votre plus proche frère ou soeur ?"},
              {"CHILDHOOD_FRIEND": "Quel est le prénom de votre meilleur(e) ami(e) d'enfance"}]))
        );
    }
    else if (locale === 'en') {
      return this.http.get<any>(endpoint + '/security-questions')
        .pipe(
          catchError(Helper.handleError('getSecurityQuestions', [{"PRIMARY_SCHOOL": "What was the name of your elementary / primary school?"}, {"HOSPITAL": "What's the name of the hospital in which you were born?"}, {"PET": "What's the name of your first pet?"}, {"NEAREST_SIBLING": "In what city or town does your nearest sibling live?"}, {"CHILDHOOD_FRIEND": "What is your childhood best friend's first name?"}]))
        );
    }
  }

  signUpUser(user: any): Observable<HttpResponse<any>> {
    let httpOptions = {};
    httpOptions['headers'] = new HttpHeaders().set('Content-Type', 'application/json');
    httpOptions['observe'] = 'response';
    return this.http.post<any>(endpoint + '/sign-up', user, httpOptions)
      .pipe(
        catchError(Helper.handleError('signUpUser', null))
      );
  }
}
