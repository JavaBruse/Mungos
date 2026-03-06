import { ComponentFixture, TestBed } from '@angular/core/testing';

import { MetricChart } from './metric-chart';

describe('MetricChart', () => {
  let component: MetricChart;
  let fixture: ComponentFixture<MetricChart>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [MetricChart]
    })
    .compileComponents();

    fixture = TestBed.createComponent(MetricChart);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
