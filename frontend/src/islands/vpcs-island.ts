import { createApp } from 'vue'
import VPCsPage from '@/components/vpcs/VPCsPage.vue'
import '@/assets/main.css'

console.log('VPCs island script loaded')

const mountPoint = document.getElementById('vpcs-app')

if (mountPoint) {
  console.log('Mount point found, creating Vue app...')

  // Parse props from data attribute
  const propsData = mountPoint.dataset.props
  const props = propsData ? JSON.parse(propsData) : {}

  // Create and mount app
  const app = createApp(VPCsPage, props)
  app.mount(mountPoint)

  console.log('Vue app mounted successfully')
} else {
  console.error('Mount point #vpcs-app not found!')
}
