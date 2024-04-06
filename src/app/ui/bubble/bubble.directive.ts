import {
  Directive,
  Input,
  ComponentRef,
  ElementRef,
  Injector,
  ViewContainerRef
} from '@angular/core';
import { BubbleComponent, BubblePosition } from './bubble.component';

@Directive({
  selector: '[bubbleTip]',
  exportAs: 'bubbleTip',
  standalone: true
})
export class BubbleDirective {

  private bubbleIndex!: number;

  @Input() bubbleTip = 'this is a HC tip';
  @Input() bubblePosition: BubblePosition = BubblePosition.DEFAULT;
  @Input() bubbleWidth?: string;
  @Input() bubbleHeight?: string;

  private componentRef: ComponentRef<BubbleComponent> | null = null;

  constructor(private elementRef: ElementRef,
    private viewContainerRef: ViewContainerRef,
    private injector: Injector
  ) {

  }

  public show() {
    this.initializeBubble();
  }

  public hide() {
    this.destroy();
  }

  private initializeBubble() {
    if (this.componentRef === null) {
      this.componentRef = this.viewContainerRef.createComponent(BubbleComponent,{injector: this.injector});
      this.setComponentProperties();
      this.bubbleIndex = this.viewContainerRef.indexOf(this.componentRef.hostView);
    }
  }

  private setComponentProperties() {
    if (this.componentRef !== null) {
      this.componentRef.instance.tip = this.bubbleTip;
      this.componentRef.instance.position =this.bubblePosition;
      this.componentRef.instance.width = this.bubbleWidth;
      this.componentRef.instance.height = this.bubbleHeight;

      const {left, right, top, bottom} = this.elementRef.nativeElement.getBoundingClientRect();

      switch (this.bubblePosition) {
        case BubblePosition.UPPER:
        case BubblePosition.ABOVE: {
          this.componentRef.instance.left = Math.round((right - left) / 2 + left);
          this.componentRef.instance.top = Math.round(top);
          break;
        }
        case BubblePosition.RIGHT: {
          this.componentRef.instance.left = Math.round(right);
          this.componentRef.instance.top = Math.round(top + (bottom - top) / 2);
          break;
        }
/*        case BubblePosition.BELOW: {
          this.componentRef.instance.left = Math.round((right - left) / 2 + left);
          this.componentRef.instance.top = Math.round(bottom);
          break;
        }

        case BubblePosition.LEFT: {
          this.componentRef.instance.left = Math.round(left);
          this.componentRef.instance.top = Math.round(top + (bottom - top) / 2);
          break;
        }
*/
        default: {
          console.error('unknown bubble position', this.bubblePosition);
        }
      }

      this.componentRef.instance.visible = true;
      this.componentRef.instance.changeRef.detectChanges();
    }
  }

  ngOnDestroy(): void {
    this.destroy();
  }

  destroy(): void {
    if (this.componentRef !== null) {
      this.componentRef.instance.visible = false;
      this.viewContainerRef.remove(this.bubbleIndex);
      this.componentRef.destroy();
      this.componentRef = null;
    }
  }
}

