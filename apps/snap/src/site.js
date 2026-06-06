const snapId = 'local:http://localhost:8080';
const output = document.querySelector('#output');
const connectButton = document.querySelector('#connect');
const sendNormalButton = document.querySelector('#send-normal');
const sendRiskyButton = document.querySelector('#send-risky');
const approveBscUsdtButton = document.querySelector('#approve-bsc-usdt');
const sendCustomButton = document.querySelector('#send-custom');
const customAddressInput = document.querySelector('#custom-address');

const txRiskApiUrl = 'http://localhost:8000/tx-scan';
const normalAddress = '0x1111111111111111111111111111111111111111';
const riskyAddress = '0x000000000000000000000000000000000000dead';
const pointOneEthInWeiHex = '0x16345785d8a0000';
const ethMainnetChainId = '0x1';
const bscChainId = '0x38';
const bscUsdtAddress = '0x55d398326f99059fF775485246999027B3197955';
const atalisLoanAddress = '0xfEAd9619e88464e5aD1Ea9Df458dcc147F03ea0C';
const tenUsdtWith18DecimalsHex = '0x8ac7230489e80000';

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

const scanTransactionRisk = async (payload) => {
  const response = await fetch(txRiskApiUrl, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`TxRiskAgent API returned ${response.status}.`);
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

const previewRiskReport = async (payload) => {
  print({
    status: 'Scanning transaction with TxRiskAgent...',
    request: payload,
  });

  const risk = await scanTransactionRisk(payload);

  print({
    status: 'TxRiskAgent API response',
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

  sendNormalButton.disabled = false;
  sendRiskyButton.disabled = false;
  approveBscUsdtButton.disabled = false;
  sendCustomButton.disabled = false;
  print(`Snap connected: ${snapId}`);
};

const sendTransaction = async (to) => {
  const provider = getProvider();
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
    value: pointOneEthInWeiHex,
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

const padAddressForCalldata = (address) => address.slice(2).padStart(64, '0');

const padHexQuantityForCalldata = (value) => value.slice(2).padStart(64, '0');

const buildApproveCalldata = (spender, amount) =>
  `0x095ea7b3${padAddressForCalldata(spender)}${padHexQuantityForCalldata(
    amount,
  )}`;

const switchToEthereumMainnet = async () => {
  const provider = getProvider();

  await provider.request({
    method: 'wallet_switchEthereumChain',
    params: [{ chainId: ethMainnetChainId }],
  });
};

const switchToBsc = async () => {
  const provider = getProvider();

  try {
    await provider.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: bscChainId }],
    });
  } catch (error) {
    if (error.code !== 4902) {
      throw error;
    }

    await provider.request({
      method: 'wallet_addEthereumChain',
      params: [
        {
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
      ],
    });
  }
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
    await switchToEthereumMainnet();
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
  print('MetaMask detected. Connect the local Snap to begin.');
} catch (error) {
  print(error.message);
}
