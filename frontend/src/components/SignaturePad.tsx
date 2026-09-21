import {
  type PointerEvent as ReactPointerEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { Button } from "@/components/ui";
import { PEN_WIDTH, type Point, type Stroke, shouldKeepPoint, traceStroke } from "@/lib/strokes";

interface SignaturePadProps {
  strokes: Stroke[];
  onChange: (strokes: Stroke[]) => void;
  describedBy?: string;
}

/**
 * Draw with a finger, a stylus or a mouse. Pointer events cover all three, the canvas captures
 * the pointer so a stroke that leaves the box is not cut short, and `touch-action: none` stops
 * the page from scrolling away under someone's finger mid-signature.
 *
 * Strokes are kept as points and the canvas is redrawn from them, which is what makes undo and a
 * resize (rotating the tablet) lossless.
 */
export function SignaturePad({ strokes, onChange, describedBy }: SignaturePadProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const live = useRef<Stroke | null>(null);
  const pointerId = useRef<number | null>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });

  const redraw = useCallback(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) {
      return;
    }
    const ratio = canvas.width / Math.max(1, canvas.clientWidth);
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const ink = getComputedStyle(canvas).color;
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.lineWidth = PEN_WIDTH * ratio;
    ctx.strokeStyle = ink;
    ctx.fillStyle = ink;
    for (const stroke of live.current ? [...strokes, live.current] : strokes) {
      traceStroke(ctx, stroke, 0, 0, ratio);
    }
  }, [strokes]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas === null) {
      return;
    }
    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 3);
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      setSize({ width, height });
    };
    resize();
    if (typeof ResizeObserver === "undefined") {
      return;
    }
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);
    return () => observer.disconnect();
  }, []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: a resize clears the canvas, so it must repaint
  useEffect(redraw, [redraw, size]);

  const pointFrom = (event: ReactPointerEvent<HTMLCanvasElement>): Point => {
    const rect = event.currentTarget.getBoundingClientRect();
    return { x: event.clientX - rect.left, y: event.clientY - rect.top };
  };

  const begin = (event: ReactPointerEvent<HTMLCanvasElement>) => {
    if (pointerId.current !== null || (event.pointerType === "mouse" && event.button !== 0)) {
      return;
    }
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    pointerId.current = event.pointerId;
    live.current = [pointFrom(event)];
    redraw();
  };

  const move = (event: ReactPointerEvent<HTMLCanvasElement>) => {
    const stroke = live.current;
    if (stroke === null || event.pointerId !== pointerId.current) {
      return;
    }
    // Coalesced events carry the samples the browser batched between frames: smoother curves.
    const native = event.nativeEvent;
    const samples =
      typeof native.getCoalescedEvents === "function" ? native.getCoalescedEvents() : [];
    const rect = event.currentTarget.getBoundingClientRect();
    const points: Point[] =
      samples.length > 0
        ? samples.map((sample) => ({ x: sample.clientX - rect.left, y: sample.clientY - rect.top }))
        : [pointFrom(event)];
    for (const point of points) {
      if (shouldKeepPoint(stroke[stroke.length - 1], point)) {
        stroke.push(point);
      }
    }
    redraw();
  };

  const end = (event: ReactPointerEvent<HTMLCanvasElement>) => {
    if (event.pointerId !== pointerId.current) {
      return;
    }
    const stroke = live.current;
    pointerId.current = null;
    live.current = null;
    if (stroke !== null && stroke.length > 0) {
      onChange([...strokes, stroke]);
    }
  };

  const hasInk = strokes.length > 0;

  return (
    <div>
      <div className="signature-line relative rounded-lg bg-sheet ring-[1.5px] ring-edge-strong ring-inset">
        <canvas
          ref={canvasRef}
          role="img"
          aria-label={
            hasInk
              ? "Signature drawing area. You have drawn a signature."
              : "Signature drawing area. Empty."
          }
          aria-describedby={describedBy}
          data-testid="signature-pad"
          className="block h-44 w-full cursor-crosshair touch-none rounded-lg text-pen sm:h-52"
          onPointerDown={begin}
          onPointerMove={move}
          onPointerUp={end}
          onPointerCancel={end}
        />
        {hasInk ? null : (
          <p
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-0 bottom-3 text-center text-ink-500 text-sm"
          >
            Sign above the line with your finger, a stylus or a mouse
          </p>
        )}
      </div>
      <div className="mt-3 flex flex-wrap gap-3">
        <Button
          variant="secondary"
          inert={!hasInk}
          onClick={() => hasInk && onChange(strokes.slice(0, -1))}
        >
          Undo<span className="sr-only"> last stroke</span>
        </Button>
        <Button variant="secondary" inert={!hasInk} onClick={() => hasInk && onChange([])}>
          Clear<span className="sr-only"> and start again</span>
        </Button>
      </div>
    </div>
  );
}
