import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SenderLinksComponent } from './senderlinks.component';

describe('SenderLinkComponent', () => {
  let component: SenderLinksComponent;
  let fixture: ComponentFixture<SenderLinksComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SenderLinksComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SenderLinksComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
