import { ComponentFixture, TestBed } from '@angular/core/testing';
import { VersionsComponent } from './versions.component';
import { RouterModule } from '@angular/router';

describe('VersionsComponent', () => {
  let component: VersionsComponent;
  let fixture: ComponentFixture<VersionsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [VersionsComponent,  RouterModule.forRoot([])]
    })
    .compileComponents();

    fixture = TestBed.createComponent(VersionsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
