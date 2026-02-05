import { createApp } from 'vue'
import TasksPage from '@/components/tasks/TasksPage.vue'
import '@/assets/main.css'

console.log('Tasks island script loaded')

const mountPoint = document.getElementById('tasks-app')

if (mountPoint) {
  console.log('Mount point found, creating Vue app...')

  // Parse props from data attribute
  const propsData = mountPoint.dataset.props
  const props = propsData ? JSON.parse(propsData) : {}

  // Create and mount app
  const app = createApp(TasksPage, props)
  app.mount(mountPoint)

  console.log('Vue app mounted successfully')
} else {
  console.error('Mount point #tasks-app not found!')
}
