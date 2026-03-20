import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MetricChart } from "../metrics/metric-chart/metric-chart";

@Component({
  selector: 'app-analitic',
  imports: [MatFormFieldModule, MatSelectModule, MatInputModule, FormsModule, MetricChart],
  templateUrl: './analitic.html',
  styleUrl: './analitic.scss',
})
export class Analitic {
}