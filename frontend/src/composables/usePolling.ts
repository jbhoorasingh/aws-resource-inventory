import { ref, onMounted, onUnmounted, watch, type Ref } from 'vue'

export interface UsePollingOptions {
  /** Start polling immediately on mount */
  immediate?: boolean
  /** Condition function to determine if polling should continue */
  condition?: () => boolean
}

export function usePolling(
  callback: () => Promise<void>,
  interval = 5000,
  options: UsePollingOptions = {}
) {
  const { immediate = true, condition = () => true } = options

  const isPolling = ref(false)
  const isPaused = ref(false)
  let timeoutId: number | null = null

  const poll = async () => {
    if (isPaused.value) {
      isPolling.value = false
      return
    }

    if (!condition()) {
      isPolling.value = false
      return
    }

    isPolling.value = true

    try {
      await callback()
    } catch (e) {
      console.error('Polling error:', e)
    }

    // Schedule next poll if condition still true
    if (condition() && !isPaused.value) {
      timeoutId = window.setTimeout(poll, interval)
    } else {
      isPolling.value = false
    }
  }

  const start = () => {
    isPaused.value = false
    if (timeoutId === null) {
      poll()
    }
  }

  const stop = () => {
    isPaused.value = true
    if (timeoutId !== null) {
      clearTimeout(timeoutId)
      timeoutId = null
    }
    isPolling.value = false
  }

  const restart = () => {
    stop()
    start()
  }

  onMounted(() => {
    if (immediate) {
      start()
    }
  })

  onUnmounted(() => {
    stop()
  })

  return {
    isPolling,
    isPaused,
    start,
    stop,
    restart,
  }
}

// Variant that polls only when a condition ref is true
export function useConditionalPolling(
  callback: () => Promise<void>,
  shouldPoll: Ref<boolean>,
  interval = 5000
) {
  const { isPolling, start, stop } = usePolling(callback, interval, {
    immediate: false,
    condition: () => shouldPoll.value,
  })

  // Watch the condition and start/stop accordingly
  watch(
    shouldPoll,
    (newValue) => {
      if (newValue) {
        start()
      } else {
        stop()
      }
    },
    { immediate: true }
  )

  return {
    isPolling,
    start,
    stop,
  }
}
