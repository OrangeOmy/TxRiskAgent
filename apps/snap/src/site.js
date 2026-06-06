const snapId = 'local:http://localhost:8080';
const output = document.querySelector('#output');
const connectButton = document.querySelector('#connect');
const sendNormalButton = document.querySelector('#send-normal');
const sendRiskyButton = document.querySelector('#send-risky');
const approveBscUsdtButton = document.querySelector('#approve-bsc-usdt');
const sendCustomButton = document.querySelector('#send-custom');
const customAddressInput = document.querySelector('#custom-address');
const endpointSelect = document.querySelector('#endpoint-select');
const networkSelect = document.querySelector('#network-select');

const txRiskEndpoints = {
  local: {
    label: 'Local dev',
    url: 'http://localhost:8000/tx-scan',
    apiKey: 'test-key',
  },
  prod: {
    label: 'Remote prod',
    url: 'https://txriskagent-production.up.railway.app/tx-scan',
    apiKey: 'change-me',
  },
};
const normalAddress = '0x1111111111111111111111111111111111111111';
const riskyAddress = '0x000000000000000000000000000000000000dead';
const pointOneNativeTokenInWeiHex = '0x16345785d8a0000';
const ethMainnetChainId = '0x1';
const bscChainId = '0x38';
const nativeNetworks = {
  eth: {
    label: 'ETH',
    chainId: ethMainnetChainId,
    nativeSymbol: 'ETH',
  },
  bnb: {
    label: 'BNB',
    chainId: bscChainId,
    nativeSymbol: 'BNB',
    addEthereumChain: {
      chainId: bscChainId,
      chainName: 'BNB Smart Chain',
      nativeCurrency: {
        name: 'BNB',
        symbol: 'BNB',
        decimals: 18,
      },
      rpcUrls: ['https://bsc-dataseed.binance.org/'],
      blockExplorerUrls: ['https://bscscan.com'],
    },
  },
};
const bscUsdtAddress = '0x55d398326f99059fF775485246999027B3197955';
const atalisLoanAddress = '0xfEAd9619e88464e5aD1Ea9Df458dcc147F03ea0C';
const tenUsdtWith18DecimalsHex = '0x8ac7230489e80000';
let snapConnected = false;

const print = (value) => {
  output.textContent =
    typeof value === 'string' ? value : JSON.stringify(value, null, 2);
};

const getProvider = () => {
  if (!window.ethereum) {
    throw new Error('MetaMask is not available in this browser.');
  }

  return window.ethereum;
};

const hexChainIdToCaip2 = (chainId) => `eip155:${Number.parseInt(chainId, 16)}`;

const getCurrentCaip2ChainId = async (provider) => {
  const chainId = await provider.request({ method: 'eth_chainId' });

  return hexChainIdToCaip2(chainId);
};

const getSelectedEndpoint = () => {
  const selectedKey = endpointSelect.value;

  return txRiskEndpoints[selectedKey] ?? txRiskEndpoints.local;
};

const getSelectedNativeNetwork = () => {
  const selectedKey = networkSelect.value;

  return nativeNetworks[selectedKey] ?? nativeNetworks.eth;
};

const syncSnapEndpoint = async () => {
  const provider = getProvider();
  const endpointKey = endpointSelect.value;

  return provider.request({
    method: 'wallet_invokeSnap',
    params: {
      snapId,
      request: {
        method: 'setEndpoint',
        params: {
          endpoint: endpointKey,
        },
      },
    },
  });
};

const scanTransactionRisk = async (payload) => {
  const endpoint = getSelectedEndpoint();
  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };

  if (endpoint.apiKey) {
    headers['X-API-Key'] = endpoint.apiKey;
  }

  const response = await fetch(endpoint.url, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(
      `${endpoint.label} TxRiskAgent API returned ${response.status}.`,
    );
  }

  return response.json();
};

const selectRiskReportFields = (risk) => ({
  schemaVersion: risk.schemaVersion,
  inputRef: risk.inputRef,
  verdict: risk.verdict,
  summary: risk.summary,
  intent: risk.intent,
  assetImpact: risk.assetImpact,
  riskFactors: risk.riskFactors,
  evidence: risk.evidence,
  recommendation: risk.recommendation,
});

const previewRiskReport = async (payload, context = {}) => {
  const endpoint = getSelectedEndpoint();

  print({
    status: `Scanning transaction with TxRiskAgent (${endpoint.label})...`,
    endpoint: endpoint.url,
    ...context,
    request: payload,
  });

  const risk = await scanTransactionRisk(payload);

  print({
    status: `TxRiskAgent API response (${endpoint.label})`,
    endpoint: endpoint.url,
    ...context,
    response: selectRiskReportFields(risk),
  });

  return risk;
};

const requestSnaps = async () => {
  const provider = getProvider();

  await provider.request({
    method: 'wallet_requestSnaps',
    params: {
      [snapId]: {},
    },
  });
  const endpoint = await syncSnapEndpoint();
  snapConnected = true;

  sendNormalButton.disabled = false;
  sendRiskyButton.disabled = false;
  approveBscUsdtButton.disabled = false;
  sendCustomButton.disabled = false;
  print({
    status: `Snap connected: ${snapId}`,
    endpoint,
  });
};

const sendTransaction = async (to) => {
  const provider = getProvider();
  await switchToSelectedNativeNetwork();
  const network = getSelectedNativeNetwork();

  const accounts = await provider.request({
    method: 'eth_requestAccounts',
  });
  const from = accounts[0];

  if (!from) {
    throw new Error('No MetaMask account is connected.');
  }

  const transaction = {
    from,
    to,
    value: pointOneNativeTokenInWeiHex,
  };
  const risk = await previewRiskReport({
    chainId: await getCurrentCaip2ChainId(provider),
    transactionOrigin: window.location.origin,
    transaction,
  }, {
    network: network.label,
    asset: network.nativeSymbol,
  });

  const txHash = await provider.request({
    method: 'eth_sendTransaction',
    params: [transaction],
  });

  print({
    status: `Transaction submitted on ${network.label}`,
    txHash,
    network: network.label,
    response: selectRiskReportFields(risk),
  });
};

const padAddressForCalldata = (address) => address.slice(2).padStart(64, '0');

const padHexQuantityForCalldata = (value) => value.slice(2).padStart(64, '0');

const buildApproveCalldata = (spender, amount) =>
  `0x095ea7b3${padAddressForCalldata(spender)}${padHexQuantityForCalldata(
    amount,
  )}`;

const switchToNetwork = async (network) => {
  const provider = getProvider();

  try {
    await provider.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: network.chainId }],
    });
  } catch (error) {
    if (error.code !== 4902 || !network.addEthereumChain) {
      throw error;
    }

    await provider.request({
      method: 'wallet_addEthereumChain',
      params: [network.addEthereumChain],
    });
  }
};

const switchToSelectedNativeNetwork = async () => {
  await switchToNetwork(getSelectedNativeNetwork());
};

const switchToBsc = async () => {
  await switchToNetwork(nativeNetworks.bnb);
};

const approveBscUsdt = async () => {
  const provider = getProvider();
  await switchToBsc();

  const accounts = await provider.request({
    method: 'eth_requestAccounts',
  });
  const from = accounts[0];

  if (!from) {
    throw new Error('No MetaMask account is connected.');
  }

  const transaction = {
    from,
    to: bscUsdtAddress,
    value: '0x0',
    data: buildApproveCalldata(atalisLoanAddress, tenUsdtWith18DecimalsHex),
  };
  const risk = await previewRiskReport({
    chainId: await getCurrentCaip2ChainId(provider),
    transactionOrigin: window.location.origin,
    transaction,
  });

  const txHash = await provider.request({
    method: 'eth_sendTransaction',
    params: [transaction],
  });

  print({
    status: 'Transaction submitted',
    txHash,
    response: selectRiskReportFields(risk),
  });
};

connectButton.addEventListener('click', async () => {
  try {
    await requestSnaps();
  } catch (error) {
    print(error.message);
  }
});

sendNormalButton.addEventListener('click', async () => {
  try {
    await sendTransaction(normalAddress);
  } catch (error) {
    print(error.message);
  }
});

sendRiskyButton.addEventListener('click', async () => {
  try {
    await sendTransaction(riskyAddress);
  } catch (error) {
    print(error.message);
  }
});

approveBscUsdtButton.addEventListener('click', async () => {
  try {
    await approveBscUsdt();
  } catch (error) {
    print(error.message);
  }
});

endpointSelect.addEventListener('change', async () => {
  const endpoint = getSelectedEndpoint();

  if (!snapConnected) {
    print({
      status: `Selected TxRisk endpoint: ${endpoint.label}`,
      endpoint: endpoint.url,
    });
    return;
  }

  try {
    const snapEndpoint = await syncSnapEndpoint();

    print({
      status: 'Snap TxRisk endpoint updated',
      endpoint: snapEndpoint,
    });
  } catch (error) {
    print(error.message);
  }
});

sendCustomButton.addEventListener('click', async () => {
  try {
    const to = customAddressInput.value.trim();

    if (!/^0x[a-fA-F0-9]{40}$/.test(to)) {
      throw new Error('Enter a valid 0x address.');
    }

    await sendTransaction(to);
  } catch (error) {
    print(error.message);
  }
});

try {
  getProvider();
  print('MetaMask detected. Select a TxRisk endpoint, then connect the local Snap to begin.');
} catch (error) {
  print(error.message);
}
