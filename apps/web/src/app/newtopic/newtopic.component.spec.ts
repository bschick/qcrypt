import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NewTopicComponent } from './newtopic.component';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

describe('NewTopicComponent', () => {
  let component: NewTopicComponent;
  let fixture: ComponentFixture<NewTopicComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [NewTopicComponent, RouterModule.forRoot([]), NoopAnimationsModule],
      providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
    }).compileComponents();

    fixture = TestBed.createComponent(NewTopicComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

