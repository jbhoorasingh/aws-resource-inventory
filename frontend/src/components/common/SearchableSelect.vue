<template>
  <Combobox v-model="selected" :multiple="multiple" :disabled="disabled" as="div">
    <div class="relative">
      <div class="relative w-full">
        <ComboboxInput
          class="w-full border border-gray-300 rounded-md py-2 pl-3 pr-10 text-sm
                 focus:ring-2 focus:ring-aws-orange focus:border-aws-orange
                 disabled:bg-gray-100 disabled:cursor-not-allowed"
          :displayValue="(item: unknown) => getDisplayValue(item as SelectOption | SelectOption[] | null)"
          @change="query = $event.target.value"
          :placeholder="placeholder"
        />
        <ComboboxButton
          class="absolute inset-y-0 right-0 flex items-center pr-2"
        >
          <ChevronUpDownIcon
            class="h-5 w-5 text-gray-400"
            aria-hidden="true"
          />
        </ComboboxButton>
      </div>

      <TransitionRoot
        leave="transition ease-in duration-100"
        leaveFrom="opacity-100"
        leaveTo="opacity-0"
        @after-leave="query = ''"
      >
        <ComboboxOptions
          class="absolute z-50 mt-1 max-h-60 w-full overflow-auto rounded-md bg-white
                 py-1 text-sm shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none"
        >
          <!-- Loading state -->
          <div v-if="loading" class="px-4 py-2 text-gray-500 flex items-center">
            <LoadingSpinner size="small" class="mr-2" />
            Loading...
          </div>

          <!-- Clear option -->
          <ComboboxOption
            v-if="clearable && !multiple && selected"
            :value="null"
            v-slot="{ active }"
            as="template"
          >
            <li
              :class="[
                'relative cursor-pointer select-none py-2 pl-10 pr-4',
                active ? 'bg-gray-100 text-gray-900' : 'text-gray-500',
              ]"
            >
              <span class="block truncate italic">Clear selection</span>
            </li>
          </ComboboxOption>

          <!-- No results -->
          <div
            v-if="!loading && filteredOptions.length === 0 && query !== ''"
            class="px-4 py-2 text-gray-500"
          >
            No results found for "{{ query }}"
          </div>

          <!-- Options -->
          <ComboboxOption
            v-for="option in filteredOptions"
            :key="option.value ?? 'null'"
            :value="option"
            v-slot="{ active, selected: isSelected }"
            as="template"
          >
            <li
              :class="[
                'relative cursor-pointer select-none py-2 pl-10 pr-4',
                active ? 'bg-aws-orange text-white' : 'text-gray-900',
              ]"
            >
              <span :class="['block truncate', isSelected && 'font-medium']">
                {{ option.label }}
              </span>
              <span
                v-if="option.sublabel"
                :class="[
                  'block text-xs mt-0.5',
                  active ? 'text-orange-100' : 'text-gray-500',
                ]"
              >
                {{ option.sublabel }}
              </span>
              <span
                v-if="isSelected"
                :class="[
                  'absolute inset-y-0 left-0 flex items-center pl-3',
                  active ? 'text-white' : 'text-aws-orange',
                ]"
              >
                <CheckIcon class="h-5 w-5" aria-hidden="true" />
              </span>
            </li>
          </ComboboxOption>
        </ComboboxOptions>
      </TransitionRoot>
    </div>
  </Combobox>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import {
  Combobox,
  ComboboxInput,
  ComboboxButton,
  ComboboxOptions,
  ComboboxOption,
  TransitionRoot,
} from '@headlessui/vue'
import { CheckIcon, ChevronUpDownIcon } from '@heroicons/vue/20/solid'
import LoadingSpinner from './LoadingSpinner.vue'

export interface SelectOption {
  value: string | number | null
  label: string
  sublabel?: string
}

const props = withDefaults(
  defineProps<{
    modelValue: SelectOption | SelectOption[] | null
    options: SelectOption[]
    placeholder?: string
    multiple?: boolean
    disabled?: boolean
    loading?: boolean
    clearable?: boolean
  }>(),
  {
    placeholder: 'Select...',
    multiple: false,
    disabled: false,
    loading: false,
    clearable: true,
  }
)

const emit = defineEmits<{
  (e: 'update:modelValue', value: SelectOption | SelectOption[] | null): void
}>()

const query = ref('')

const selected = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value),
})

const filteredOptions = computed(() => {
  if (query.value === '') return props.options

  const searchTerms = query.value.toLowerCase().split(' ').filter(Boolean)
  return props.options.filter((option) => {
    const searchText = `${option.label} ${option.sublabel || ''}`.toLowerCase()
    return searchTerms.every((term) => searchText.includes(term))
  })
})

const getDisplayValue = (item: SelectOption | SelectOption[] | null): string => {
  if (!item) return ''
  if (Array.isArray(item)) {
    if (item.length === 0) return ''
    if (item.length === 1) return item[0].label
    return `${item.length} selected`
  }
  return item.label
}
</script>
