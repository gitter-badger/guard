import {Component, OnInit} from '@angular/core';
import {AppService} from "./app.service";
import {TranslateService} from "./shared/i18n/translate.service";

@Component({
    selector: 'guard-root',
    templateUrl: './app.component.html'
})
export class AppComponent implements OnInit {

  constructor(private service: AppService) {
  }

  context: any;

  ngOnInit(): void {
    this.service.getContext().subscribe((result: any) => {
      this.context = result;
    });
  }
}
