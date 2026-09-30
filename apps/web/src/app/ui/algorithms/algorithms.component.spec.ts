import { ComponentFixture, TestBed } from '@angular/core/testing';
import type { HarnessLoader } from '@angular/cdk/testing';
import { TestbedHarnessEnvironment } from '@angular/cdk/testing/testbed';
import { MatButtonToggleGroupHarness } from '@angular/material/button-toggle/testing';

import { AlgorithmsComponent } from './algorithms.component';

describe('AlgorithmsComponent', () => {
   let component: AlgorithmsComponent;
   let fixture: ComponentFixture<AlgorithmsComponent>;
   let loader: HarnessLoader;

   beforeEach(async () => {
      await TestBed.configureTestingModule({
         imports: [AlgorithmsComponent],
      }).compileComponents();

      fixture = TestBed.createComponent(AlgorithmsComponent);
      component = fixture.componentInstance;
      loader = TestbedHarnessEnvironment.loader(fixture);
      fixture.detectChanges();
   });

   it('should create', () => {
      expect(component).toBeTruthy();
   });

   it('renders the algorithm column as Material table cells', () => {
      fixture.componentRef.setInput('count', 2);
      fixture.detectChanges();

      const cells: Element[] = [...fixture.nativeElement.querySelectorAll('td.alg')];
      expect(cells.length).toBe(2);
      for (const cell of cells) {
         expect(cell.classList).toContain('mat-mdc-cell');
      }
   });

   it('reports the mode of every loop when one changes, without rebuilding the rows', async () => {
      fixture.componentRef.setInput('modes', ['AES-GCM']);
      fixture.componentRef.setInput('count', 3);
      fixture.detectChanges();
      const reported: string[][] = [];
      component.modes.subscribe((modes) => reported.push([...modes]));
      const rowsBefore: Element[] = [...fixture.nativeElement.querySelectorAll('tr')];

      const groups = await loader.getAllHarnesses(MatButtonToggleGroupHarness);
      expect(groups.length).toBe(3);
      const [aesInLoop3] = await groups[2].getToggles({ text: 'AES 256 GCM' });
      await aesInLoop3.check();

      expect(reported).toEqual([['AES-GCM', 'X20-PLY', 'AES-GCM']]);
      expect(await aesInLoop3.isChecked()).toBe(true);
      const rowsAfter: Element[] = [...fixture.nativeElement.querySelectorAll('tr')];
      expect(rowsAfter.length).toBe(rowsBefore.length);
      for (const [index, row] of rowsAfter.entries()) {
         expect(row).toBe(rowsBefore[index]);
      }
   });

   it('keeps modes chosen for loops beyond the current count', async () => {
      fixture.componentRef.setInput('modes', ['AES-GCM', 'AEGIS-256', 'AES-GCM']);
      fixture.componentRef.setInput('count', 1);
      fixture.detectChanges();
      const reported: string[][] = [];
      component.modes.subscribe((modes) => reported.push([...modes]));

      const [group] = await loader.getAllHarnesses(MatButtonToggleGroupHarness);
      const [x20] = await group.getToggles({ text: 'XChaCha20 Poly1305' });
      await x20.check();

      expect(reported).toEqual([['X20-PLY', 'AEGIS-256', 'AES-GCM']]);
   });
});
