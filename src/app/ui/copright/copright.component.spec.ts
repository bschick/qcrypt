import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CoprightComponent } from './copright.component';

describe('CoprightComponent', () => {
  let component: CoprightComponent;
  let fixture: ComponentFixture<CoprightComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CoprightComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CoprightComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
