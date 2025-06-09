import { ComponentFixture, TestBed } from '@angular/core/testing';
import { SenderLinksComponent } from './senderlinks.component';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

describe('SenderLinkComponent', () => {
  let component: SenderLinksComponent;
  let fixture: ComponentFixture<SenderLinksComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SenderLinksComponent, RouterModule.forRoot([]), NoopAnimationsModule],
      providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
    }).compileComponents();

    fixture = TestBed.createComponent(SenderLinksComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
