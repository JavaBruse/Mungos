import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatTableModule } from '@angular/material/table';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { AuditLogService } from './audit-log.service';
import { Subject, debounceTime, distinctUntilChanged } from 'rxjs';
import { MatFormFieldModule } from "@angular/material/form-field";
import { MatInputModule } from '@angular/material/input';
MatInputModule
@Component({
  selector: 'app-audit-log',
  standalone: true,
  imports: [
    CommonModule,
    MatTableModule,
    MatPaginatorModule,
    MatProgressSpinnerModule,
    MatIconModule,
    MatButtonModule,
    MatTooltipModule,
    MatFormFieldModule,
    MatInputModule
  ],
  templateUrl: './audit-log.component.html',
  styleUrls: ['./audit-log.component.scss']
})
export class AuditLogComponent implements OnInit {
  private auditLogService = inject(AuditLogService);
  private searchSubject = new Subject<string>();
  searchTerm = this.auditLogService.searchTerm;
  displayedColumns: string[] = ['timestamp', 'userId', 'action', 'target', 'details', 'ipAddress'];

  logs = this.auditLogService.logs;
  totalElements = this.auditLogService.totalElements;
  pageSize = this.auditLogService.pageSize;
  currentPage = this.auditLogService.currentPage;
  loading = this.auditLogService.loading;

  ngOnInit() {
    this.auditLogService.loadPage(0, 25);
    this.searchSubject.pipe(
      debounceTime(500),
      distinctUntilChanged()
    ).subscribe(value => {
      this.auditLogService.loadPage(0, this.pageSize(), value);
    });
  }

  onSearch(event: Event) {
    const value = (event.target as HTMLInputElement).value;
    this.searchSubject.next(value);
  }

  onPageChange(event: PageEvent) {
    this.auditLogService.loadPage(event.pageIndex, event.pageSize);
  }

  refresh() {
    this.auditLogService.reload();
  }

  formatTimestamp(timestamp: number): string {
    if (!timestamp) return '';
    return new Date(timestamp).toLocaleString();
  }
}
