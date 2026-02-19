import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SnifferAddComponent } from './sniffer-add-component';

describe('SnifferAddComponent', () => {
  let component: SnifferAddComponent;
  let fixture: ComponentFixture<SnifferAddComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SnifferAddComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SnifferAddComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
