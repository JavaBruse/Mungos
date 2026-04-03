import { Component, inject, OnInit, OnDestroy, ViewChild, ElementRef } from '@angular/core';
import { Subscription } from 'rxjs';
import { ReactiveFormsModule } from '@angular/forms';
import { ActivatedRoute, RouterModule, Router } from '@angular/router';
import { HttpService } from '../../services/http.service';
import { ErrorMessageService } from '../../services/error-message.service';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatBadgeModule } from '@angular/material/badge';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatMenuModule } from '@angular/material/menu';
import { MatChipsModule } from '@angular/material/chips';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { DialogComponent } from '../../dialog/dialog.component';
import { MatDialog } from '@angular/material/dialog';
import { SnifferService } from '../service/sniffer.service';
import { SnifferAddComponent } from "../sniffer-add-component/sniffer-add-component";
import { CommonModule } from '@angular/common';
import { SnifferSettingComponent } from '../sniffer-setting-component/sniffer-setting-component';
import { SnifferMetricsService } from '../service/sniffer-metrics.service';
import { MatTooltipModule } from '@angular/material/tooltip';


@Component({
  selector: 'app-sniffers-component',
  imports: [
    CommonModule,
    RouterModule,
    ReactiveFormsModule,
    MatCardModule,
    MatChipsModule,
    MatIconModule,
    MatInputModule,
    MatFormFieldModule,
    MatBadgeModule,
    MatButtonToggleModule,
    MatMenuModule,
    MatSelectModule,
    MatButtonModule,
    MatCheckboxModule,
    SnifferAddComponent,
    SnifferSettingComponent,
    MatTooltipModule
  ],
  templateUrl: './sniffers-component.html',
  styleUrl: './sniffers-component.scss',
})
export class SniffersComponent implements OnInit, OnDestroy {
  metricsService = inject(SnifferMetricsService);
  http = inject(HttpService);
  errorMessageService = inject(ErrorMessageService);
  snifferService = inject(SnifferService);
  sniffers = this.snifferService.sniffers;
  readonly dialog = inject(MatDialog);
  isSettingsPage: boolean = false;
  private urlSubscription!: Subscription;
  route = inject(ActivatedRoute);
  private router = inject(Router);
  snifferSettingID: string | null = null;
  @ViewChild('globalJA4Input') globalJA4Input!: ElementRef<HTMLInputElement>;
  @ViewChild('globalSNIInput') globalSNIInput!: ElementRef<HTMLInputElement>;
  currentUploadSnifferId: string | null = null;

  constructor() {
    this.snifferService.loadAll();
  }

  navigateToSniffer(id: string) {
    if (!this.isSettingsPage) {
      this.router.navigate(['/sniffer', id]);
    }
  }

  ngOnInit() {
    this.urlSubscription = this.route.url.subscribe(segments => {
      this.isSettingsPage = segments[0]?.path === 'settings';
    });
  }
  ngOnDestroy() {
    this.urlSubscription?.unsubscribe();
  }

  delete(id: string) {
    this.snifferService.delete(id);
  }

  ping(id: string) {
    this.snifferService.ping(id);
  }

  openDialog(enterAnimationDuration: string, exitAnimationDuration: string, id: string): void {
    const dialogRef = this.dialog.open(DialogComponent, {
      width: '250px',
      enterAnimationDuration,
      exitAnimationDuration,
      data: {
        title: "Удаление",
        message: "Вы уверены?"
      }
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result === true) {
        this.delete(id);
      }
    });
  }

  onCardClick(id: string) {

  }

  startSetting(snifferId: string) {
    this.snifferSettingID = snifferId;
  }

  finishSetting() {
    this.snifferSettingID = null;
  }

  downloadJA4(snifferId: string) {
    if (!snifferId) return;
    this.snifferService.downloadJA4Database(snifferId);
  }

  downloadSNI(snifferId: string) {
    if (!snifferId) return;
    this.snifferService.downloadSNIDatabase(snifferId);
  }

  triggerUploadJA4(snifferId: string) {
    this.currentUploadSnifferId = snifferId;
    this.globalJA4Input.nativeElement.click();
  }

  triggerUploadSNI(snifferId: string) {
    this.currentUploadSnifferId = snifferId;
    this.globalSNIInput.nativeElement.click();
  }

  onUploadJA4FileSelected(event: Event) {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0 && this.currentUploadSnifferId) {
      this.snifferService.uploadJA4Database(this.currentUploadSnifferId, input.files[0]);
      input.value = '';
      this.currentUploadSnifferId = null;
    }
  }

  onUploadSNIFileSelected(event: Event) {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0 && this.currentUploadSnifferId) {
      this.snifferService.uploadSNIDatabase(this.currentUploadSnifferId, input.files[0]);
      input.value = '';
      this.currentUploadSnifferId = null;
    }
  }
}
