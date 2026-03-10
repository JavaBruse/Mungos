import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SnifferSettingComponent } from './sniffer-setting-component';

describe('SnifferSettingComponent', () => {
  let component: SnifferSettingComponent;
  let fixture: ComponentFixture<SnifferSettingComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SnifferSettingComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SnifferSettingComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
