import { ComponentFixture, TestBed } from '@angular/core/testing';

import { HandlerPackageComponent } from './handler-package.component';

describe('HandlerPackageComponent', () => {
  let component: HandlerPackageComponent;
  let fixture: ComponentFixture<HandlerPackageComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HandlerPackageComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(HandlerPackageComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
