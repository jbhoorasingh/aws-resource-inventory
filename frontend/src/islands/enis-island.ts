import { createApp } from 'vue'
import ENIsPage from '@/components/enis/ENIsPage.vue'
import '@/assets/main.css'

console.log('ENIs island script loaded')

const mountPoint = document.getElementById('enis-app')

if (mountPoint) {
  console.log('Mount point found, creating Vue app...')

  // Parse props from data attribute
  const propsData = mountPoint.dataset.props
  const props = propsData ? JSON.parse(propsData) : {}

  // Create and mount app
  const app = createApp(ENIsPage, props)
  app.mount(mountPoint)

  console.log('Vue app mounted successfully')
} else {
  console.error('Mount point #enis-app not found!')
}
