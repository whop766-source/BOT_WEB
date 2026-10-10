
const axios = require('axios');

async function call(provider, params = {}) {
  if (!provider?.api_url || !provider?.api_key) {
    throw new Error('Provider API URL or API key missing');
  }

  const body = new URLSearchParams({
    key: provider.api_key,
    ...Object.fromEntries(
      Object.entries(params).map(([key, value]) => [
        key,
        String(value)
      ])
    )
  });

  const response = await axios.post(
    provider.api_url,
    body.toString(),
    {
      timeout: 25000,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json'
      }
    }
  );

  const data = response.data;

  if (
    data &&
    !Array.isArray(data) &&
    typeof data === 'object' &&
    data.error
  ) {
    throw new Error(String(data.error));
  }

  if (data == null || typeof data !== 'object') {
    throw new Error('Invalid provider response');
  }

  return data;
}

module.exports = {
  services: (provider) =>
    call(provider, { action: 'services' }),

  add: (provider, service, link, quantity) =>
    call(provider, {
      action: 'add',
      service,
      link,
      quantity
    }),

  status: (provider, order) =>
    call(provider, {
      action: 'status',
      order
    }),

  balance: (provider) =>
    call(provider, { action: 'balance' }),

  refill: (provider, order) =>
    call(provider, {
      action: 'refill',
      order
    }),

  cancel: (provider, order) =>
    call(provider, {
      action: 'cancel',
      order
    })
};
