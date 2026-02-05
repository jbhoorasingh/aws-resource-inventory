import { createApp } from 'vue'
import AccountsPage from '@/components/accounts/AccountsPage.vue'
import '@/assets/main.css'

console.log('Accounts island script loaded')

const mountPoint = document.getElementById('accounts-app')

if (mountPoint) {
  console.log('Mount point found, creating Vue app...')

  // Parse props from data attribute
  const propsData = mountPoint.dataset.props
  const props = propsData ? JSON.parse(propsData) : {}

  // Create and mount app
  const app = createApp(AccountsPage, props)
  app.mount(mountPoint)

  console.log('Vue app mounted successfully')
} else {
  console.error('Mount point #accounts-app not found!')
}
