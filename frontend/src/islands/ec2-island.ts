import { createApp } from 'vue'
import EC2InstancesPage from '@/components/ec2/EC2InstancesPage.vue'
import '@/assets/main.css'

console.log('EC2 Instances island script loaded')

const mountPoint = document.getElementById('ec2-app')

if (mountPoint) {
  console.log('Mount point found, creating Vue app...')

  // Parse props from data attribute
  const propsData = mountPoint.dataset.props
  const props = propsData ? JSON.parse(propsData) : {}

  // Create and mount app
  const app = createApp(EC2InstancesPage, props)
  app.mount(mountPoint)

  console.log('Vue app mounted successfully')
} else {
  console.error('Mount point #ec2-app not found!')
}
