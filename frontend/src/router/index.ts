import { createRouter, createWebHistory } from 'vue-router'
import WelcomeView from '../views/WelcomeView.vue'
import RegisterView from '@/views/RegisterView.vue'
import LoginView from '@/views/LoginView.vue'
import ManageView from '@/views/ManageView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'welcome',
      component: WelcomeView
    },
    {
      path: "/register",
      name: "register",
      component: RegisterView
    },
    {
      path: "/manage",
      name: "manage",
      component: ManageView
    },
    {
      path: "/login",
      name: "login",
      component: LoginView
    }
  ]
})

export default router
