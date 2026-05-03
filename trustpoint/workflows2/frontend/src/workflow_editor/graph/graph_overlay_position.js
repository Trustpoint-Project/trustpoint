export function clamp(value, min, max) {
  return Math.max(min, Math.min(value, max));
}

function viewportLimit(size, panelSize, padding) {
  return Math.max(padding, size - panelSize - padding);
}

function toViewportX(viewport, value) {
  return value - (viewport?.scrollLeft || 0);
}

function toViewportY(viewport, value) {
  return value - (viewport?.scrollTop || 0);
}

export function measureOverlayViewport(canvasWrapEl) {
  return {
    width: canvasWrapEl?.clientWidth || 320,
    height: canvasWrapEl?.clientHeight || 240,
    scrollLeft: canvasWrapEl?.scrollLeft || 0,
    scrollTop: canvasWrapEl?.scrollTop || 0,
  };
}

export function fitPanelToViewport(
  viewport,
  {
    panelWidth,
    panelHeight,
    minWidth = 220,
    minHeight = 180,
    padding = 12,
  },
) {
  const availableWidth = Math.max(160, (viewport?.width || 320) - padding * 2);
  const availableHeight = Math.max(160, (viewport?.height || 240) - padding * 2);
  const maxWidth = availableWidth;
  const maxHeight = availableHeight;

  return {
    width: Math.max(Math.min(panelWidth, maxWidth), Math.min(minWidth, maxWidth)),
    height: Math.max(Math.min(panelHeight, maxHeight), Math.min(minHeight, maxHeight)),
    maxWidth,
    maxHeight,
  };
}

export function placePanelNearNode(viewport, pos, { panelWidth, panelHeight, padding = 12, gap = 18 }) {
  const nodeLeft = toViewportX(viewport, pos.x);
  const nodeRight = toViewportX(viewport, pos.x + pos.w);
  const nodeTop = toViewportY(viewport, pos.y);
  const fitsRight = nodeRight + gap + panelWidth <= viewport.width - padding;
  const fitsLeft = nodeLeft - gap - panelWidth >= padding;

  let left = fitsRight || !fitsLeft
    ? nodeRight + gap
    : nodeLeft - panelWidth - gap;

  left = clamp(left, padding, viewportLimit(viewport.width, panelWidth, padding));

  const top = clamp(
    nodeTop - 10,
    padding,
    viewportLimit(viewport.height, panelHeight, padding),
  );

  return { left, top };
}

export function placePanelNearPoint(viewport, point, { panelWidth, panelHeight, padding = 12, gap = 14 }) {
  const pointX = toViewportX(viewport, point.x);
  const pointY = toViewportY(viewport, point.y);
  const preferRight = pointX + gap + panelWidth <= viewport.width - padding;
  const preferBelow = pointY + gap + panelHeight <= viewport.height - padding;

  const rawLeft = preferRight ? pointX + gap : pointX - panelWidth - gap;
  const rawTop = preferBelow ? pointY + gap : pointY - panelHeight - gap;

  return {
    left: clamp(rawLeft, padding, viewportLimit(viewport.width, panelWidth, padding)),
    top: clamp(rawTop, padding, viewportLimit(viewport.height, panelHeight, padding)),
  };
}
