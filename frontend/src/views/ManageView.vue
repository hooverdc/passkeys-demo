<script setup lang="ts">

import { ref, onMounted } from "vue";

type WebauthnListResonse = {
    success: boolean,
    error: string,
    authenticators: {
        id: string,
        createdOn: string
    }[]
}

const authns = ref<WebauthnListResonse["authenticators"] | null>(null)

onMounted(async () => {
    const response = await fetch(
        `/webauthn/list`
    );
    const body = await response.json() as WebauthnListResonse;
    if (body.success) {
        authns.value = body.authenticators;
    }
    console.log(body);
});

const deleteAuthenticator = async (id: string) => {
    fetch(`/webauthn/delete?id=${id}`, {
        method: "DELETE"
    })
}

</script>

<template>
    <div class="container">
        <div class="row">
            <div class="col">
                <h2>Manage</h2>

                <h3>Authenticators</h3>
                <table class="table" v-if="authns">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Created On</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="authn in authns">
                            <td>{{ authn.id }}</td>
                            <th>{{ authn.createdOn }}</th>
                            <td>
                                <button class="btn btn-primary" @click="deleteAuthenticator(authn.id)">Delete</button>
                            </td>
                        </tr>
                    </tbody>
                </table>

            </div>
        </div>
    </div>
</template>
