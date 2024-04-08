import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { CoreComponent } from './core.component';
import { RouterModule } from '@angular/router';

describe('CoreComponent', () => {
  let component: CoreComponent;
  let fixture: ComponentFixture<CoreComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CoreComponent, HttpClientTestingModule, NoopAnimationsModule, RouterModule.forRoot([]),]
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
