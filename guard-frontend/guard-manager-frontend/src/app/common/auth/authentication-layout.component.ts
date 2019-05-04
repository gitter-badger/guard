import { Component, OnInit } from '@angular/core';

@Component({
    selector: 'guard-dashboard',
    template: '<router-outlet></router-outlet>',
})
export class AuthenticationLayoutComponent implements OnInit {

    constructor() { }

    ngOnInit(): void { }
}
