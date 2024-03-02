<script setup lang="ts">
import { RouterLink, RouterView } from 'vue-router'
</script>

<template>
  <!-- TODO bg color -->
  <div class="container">
    <div class="row">
      <div class="col">
        <h1>Passkeys Demo</h1>
      </div>
    </div>
  </div>

  <!-- TODO bg color -->

  <div class="container">


    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <ul class="navbar-nav">
        <li class="nav-item">
          <RouterLink to="/" class="nav-link">Welcome</RouterLink>
        </li>
        <li class="nav-item">
          <RouterLink to="/register" class="nav-link">Register</RouterLink>
        </li>
        <li class="nav-item">
          <RouterLink to="/login" class="nav-link">Login</RouterLink>
        </li>
        <li class="nav-item">
          <RouterLink to="/logout" class="nav-link">Logout</RouterLink>
        </li>
        <li class="nav-item">
          <RouterLink to="/manage" class="nav-link"></RouterLink>
        </li>
      </ul>
    </nav>
  </div>

  <RouterView />
</template>
