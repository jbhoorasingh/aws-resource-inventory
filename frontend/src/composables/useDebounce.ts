import { ref, watch, type Ref } from 'vue'

export function useDebounce<T>(value: Ref<T>, delay = 300): Ref<T> {
  const debouncedValue = ref(value.value) as Ref<T>
  let timeoutId: number | null = null

  watch(value, (newValue) => {
    if (timeoutId !== null) {
      clearTimeout(timeoutId)
    }

    timeoutId = window.setTimeout(() => {
      debouncedValue.value = newValue
    }, delay)
  })

  return debouncedValue
}

export function useDebouncedFn<T extends (...args: unknown[]) => unknown>(
  fn: T,
  delay = 300
): (...args: Parameters<T>) => void {
  let timeoutId: number | null = null

  return (...args: Parameters<T>) => {
    if (timeoutId !== null) {
      clearTimeout(timeoutId)
    }

    timeoutId = window.setTimeout(() => {
      fn(...args)
    }, delay)
  }
}
