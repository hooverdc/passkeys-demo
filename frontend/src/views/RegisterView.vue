<script setup lang="ts">

import { base64URLToBuffer, bufferToBase64URL } from "@/lib/webauthn";
import { ref } from "vue"

type ComponentState = "initial" | "loading" | "success" | "failure";
const componentState = ref<ComponentState>("initial");
const error = ref("");

const username = ref("");
const password = ref("");

const registerWithPassword = async () => {
  try {
    const response = await fetch(`/password/register`, {
      method: "POST",
      body: JSON.stringify({
        "user_name": username.value,
        "password": password.value
      }),
      headers: {
        "Content-Type": "application/json"
      }
    })
    const body = await response.json();
    if (body.success == false) {
      error.value = body.error;
      componentState.value = "failure"
    } else {
      componentState.value = "success"
    }
  } catch (err) {
    console.log(err)
  }
}

const registerWithPasskey = async () => {

  // get webauthn options from server

  let response = await fetch(
    `/webauthn/register/options?user_name=${username.value}`
  );
  let options = await response.json();
  console.log(options)

  options.user.id = base64URLToBuffer(options.user.id);
  options.challenge = base64URLToBuffer(options.challenge);
  options.excludeCredentials = options.excludeCredentials.map(credential => {
    return {
      id: base64URLToBuffer(credential.id),
      type: credential.type,
    }
  })

  // prompt for authenticator
  const credential = await navigator.credentials.create({
    publicKey: options
  }) as Omit<PublicKeyCredential, "response"> & {
    response: AuthenticatorAttestationResponse
  };
  console.log(credential)

  // convert Uint8Arays to Base64URL for sending back to server
  const credentialJSON = {
    authenticatorAttachment: credential.authenticatorAttachment,
    id: credential.id,
    rawId: bufferToBase64URL(credential.rawId),
    response: {
      attestationObject: bufferToBase64URL(credential.response.attestationObject),
      clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
    },
    type: "public-key"
  }

  try {
    response = await fetch(`/webauthn/register`, {
      method: "POST",
      body: JSON.stringify(credentialJSON),
      headers: {
        "Content-Type": "application/json"
      }
    });
    let body = await response.json();
    console.log(body)
    if (body.success == false) {
      error.value = body.error;
      componentState.value = "failure"
    } else {
      componentState.value = "success"
    }
  } catch (err) {
    console.log(err);
  }
}

</script>

<template>
  <div class="container">
    <div class="row">
      <div class="col">
        <h2>Register</h2>
        <p>Register with a password or passkey.</p>

        <form v-if="componentState == 'initial'">
          <div class="form-group mb-3">
            <label for="usernameControl" class="form-label">Username</label>
            <input type="text" class="form-control" id="usernameControl" autocomplete="username" v-model="username">
          </div>
          <div class="form-group mb-3">
            <label for="passwordControl" class="form-label">Password</label>
            <input type="password" class="form-control" id="passwordControl" autocomplete="password" v-model="password">
          </div>
          <div class="d-flex">
            <button class="btn btn-primary me-3" @click.prevent="registerWithPassword">Register with password</button>
            <button class="btn btn-primary" @click.prevent="registerWithPasskey">Register with passkey</button>
          </div>

        </form>
        <!-- spinner -->
        <div class="spinner-border" role="status" v-if="componentState == 'loading'">
          <span class="visually-hidden">Loading...</span>
        </div>
        <!-- failure -->
        <div class="alert alert-warning" v-if="componentState == 'failure'">
          <p>
            {{ error }}
          </p>
        </div>
        <!-- sucess -->
        <div class="alert alert-primary" v-if="componentState == 'success'">
          <p>
            Account succesfully registered.
          </p>
        </div>

      </div>
    </div>
  </div>
</template>
