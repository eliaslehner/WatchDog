module.exports = {
  env: {
    NEXT_PUBLIC_SECRET_KEY: process.env.SECRET_KEY,
  },
  headers: async () => [{
    source: '/(.*)',
    headers: [
      { key: 'Access-Control-Allow-Origin', value: '*' },
    ],
  }],
}
