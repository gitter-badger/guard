import { BrowserModule } from '@angular/platform-browser';
import {APP_INITIALIZER, NgModule} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { HttpClientModule } from '@angular/common/http';


//Directives
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';
import { PerfectScrollbarModule } from 'ngx-perfect-scrollbar';

// Routing Module
import { AppRoutes } from './app.routing';

// App Component
import { AppComponent } from './app.component';
import {ConsentComponent} from "./consent/consent.component";
import {ConsentService} from "./consent/consent.service";
import {DataTablesModule} from "angular-datatables";
import {AppService} from "./app.service";
import {TranslateService} from "./shared/i18n/translate.service";
import {TranslateModule} from "./shared/i18n/translate.module";

// Translation pipe
export function setupTranslateFactory(
  service: TranslateService): Function {
  return () => service.use(window.navigator.language);
}

@NgModule({
  imports: [
    BrowserModule,
    RouterModule.forRoot(AppRoutes, { useHash: true }),
    NgbModule.forRoot(),
    FormsModule,
    PerfectScrollbarModule,
    HttpClientModule,
    DataTablesModule,
    TranslateModule
  ],
  declarations: [
    AppComponent,
    ConsentComponent
  ],
  exports: [
  ],
  providers: [
    AppService,
    ConsentService,
    TranslateService,
    {
      provide: APP_INITIALIZER,
      useFactory: setupTranslateFactory,
      deps: [TranslateService],
      multi: true
    }
    ],
  bootstrap: [AppComponent]
})


export class AppModule { }
