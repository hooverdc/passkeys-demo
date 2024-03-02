function base64URLToBuffer(base64URL: string) {
    const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (base64.length % 4)) % 4;
    return Uint8Array.from(atob(base64.padEnd(base64.length + padLen, '=')), c => c.charCodeAt(0));
}

function bufferToBase64URL(buffer: ArrayBuffer) {
    const bytes = new Uint8Array(buffer);
    let string = '';
    bytes.forEach(b => string += String.fromCharCode(b));

    const base64 = btoa(string);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export { base64URLToBuffer, bufferToBase64URL };