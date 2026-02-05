import { createApp } from 'vue'
import SecurityGroupsPage from '@/components/security-groups/SecurityGroupsPage.vue'
import '@/assets/main.css'

console.log('Security Groups island script loaded')

const mountPoint = document.getElementById('security-groups-app')

if (mountPoint) {
  console.log('Mount point found, creating Vue app...')

  // Parse props from data attribute
  const propsData = mountPoint.dataset.props
  const props = propsData ? JSON.parse(propsData) : {}

  // Create and mount app
  const app = createApp(SecurityGroupsPage, props)
  app.mount(mountPoint)

  console.log('Vue app mounted successfully')
} else {
  console.error('Mount point #security-groups-app not found!')
}
