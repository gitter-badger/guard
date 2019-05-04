import {HttpClient, HttpHeaders, HttpResponse} from "@angular/common/http";
import {Injectable} from "@angular/core";
import {catchError, tap} from "rxjs/internal/operators";
import {Helper} from "./common/Helper";
import {Observable} from "rxjs/Rx";
import { map } from 'rxjs/operators';
import {of} from "rxjs/index";

@Injectable({
  providedIn: 'root'
})
export class AppService {

  httpOptions = {};
  context: any = null;

  constructor(private http: HttpClient) {
    this.httpOptions['headers'] = new HttpHeaders().set('Content-Type', 'application/json');
    this.httpOptions['withCredentials'] = true;
  }

  getContext(): Observable<any> {
    if (this.context == null) {
      return this.http.get<any>( '/context', this.httpOptions)
        .pipe(
          catchError(Helper.handleError('getContext', null)),
          tap(result => this.context = result)
        );
    }
    else {
      return of(this.context);
    }
  }
}
