import {HttpClient, HttpHeaders, HttpResponse} from "@angular/common/http";
import {Injectable} from "@angular/core";
import {Observable} from "rxjs/Rx";
import {catchError} from "rxjs/internal/operators";
import {Helper} from "../common/Helper";
import {Router} from "@angular/router";

const endpoint = '/api';

@Injectable()
export class ConsentService {

  httpOptions = {};

  constructor(private http: HttpClient) {
    this.httpOptions['headers'] = new HttpHeaders().set('Content-Type',  'application/json');
    this.httpOptions['observe'] = 'response';
    this.httpOptions['withCredentials'] = true;
  }


  postConsent(body: any[]): Observable<HttpResponse<any>> {
    return this.http.post<any>(endpoint + '/consents', body, this.httpOptions)
      .pipe(
        catchError(Helper.handleError('postConsent', null))
      );
  }

  getScopes(queryParams: string): Observable<HttpResponse<any>> {
    return this.http.get<any>(endpoint + '/scopes?' + queryParams, this.httpOptions)
      .pipe(
        catchError(Helper.handleError('getScopes', null))
      );
  }

  getClient(id: string): Observable<HttpResponse<any>> {
    return this.http.get<any>(endpoint + '/clients/' + id, this.httpOptions)
      .pipe(
        catchError(Helper.handleError('getClient', null))
      );
  }
}
