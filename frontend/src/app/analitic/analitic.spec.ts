import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Analitic } from './analitic';

describe('Analitic', () => {
  let component: Analitic;
  let fixture: ComponentFixture<Analitic>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Analitic]
    })
    .compileComponents();

    fixture = TestBed.createComponent(Analitic);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
