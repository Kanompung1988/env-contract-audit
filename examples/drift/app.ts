const api = process.env.API_ENDPOINT;
const token = import.meta.env.VITE_PRIVATE_TOKEN;
const fallback = process.env.CACHE_URL ?? 'memory';
console.log(api, token, fallback);
