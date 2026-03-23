export function debounce(fn, wait) {
  let timer = null;

  return (...args) => {
    clearTimeout(timer);
    timer = window.setTimeout(() => fn(...args), wait);
  };
}