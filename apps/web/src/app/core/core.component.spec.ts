import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { CoreComponent } from './core.component';
import { RouterModule } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

describe('CoreComponent', () => {
  let component: CoreComponent;
  let fixture: ComponentFixture<CoreComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
    imports: [CoreComponent, NoopAnimationsModule, RouterModule.forRoot([])],
    providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
})
    .compileComponents();

    fixture = TestBed.createComponent(CoreComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
//    expect(true).toBeTruthy();
    expect(component).toBeTruthy();
  });
});
