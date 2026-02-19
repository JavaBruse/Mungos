import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SniffersComponent } from './sniffers-component';

describe('SniffersComponent', () => {
  let component: SniffersComponent;
  let fixture: ComponentFixture<SniffersComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SniffersComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SniffersComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
