import { ComponentFixture, TestBed } from '@angular/core/testing';

import { FirstLoginPassword } from './first-login-password';

describe('FirstLoginPassword', () => {
  let component: FirstLoginPassword;
  let fixture: ComponentFixture<FirstLoginPassword>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [FirstLoginPassword]
    })
    .compileComponents();

    fixture = TestBed.createComponent(FirstLoginPassword);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
