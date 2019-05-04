import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';
import { ThemeConstants } from '../shared/config/theme-constant';

import { DashboardRoutes } from './dashboard-routing.module';

// Dashboard Component
import { DashboardComponent } from './dashboard.component';

@NgModule({
    imports: [
        RouterModule.forChild(DashboardRoutes)
    ],
    declarations: [
        DashboardComponent
    ],
    providers: [
        ThemeConstants
    ]
})
export class DashboardModule { }
