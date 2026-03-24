import { ComponentFixture, TestBed } from '@angular/core/testing';

import { GrafanaComponent } from './grafana-component';

describe('GrafanaComponent', () => {
  let component: GrafanaComponent;
  let fixture: ComponentFixture<GrafanaComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [GrafanaComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(GrafanaComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
