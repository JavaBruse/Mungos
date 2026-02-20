import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SnifferWebsocketComponent } from './sniffer-websocket-component';

describe('SnifferWebsocketComponent', () => {
  let component: SnifferWebsocketComponent;
  let fixture: ComponentFixture<SnifferWebsocketComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SnifferWebsocketComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SnifferWebsocketComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
