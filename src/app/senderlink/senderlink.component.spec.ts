import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SenderLinkComponent } from './senderlink.component';

describe('SenderLinkComponent', () => {
  let component: SenderLinkComponent;
  let fixture: ComponentFixture<SenderLinkComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SenderLinkComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SenderLinkComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
