import type {
  OnRpcRequestHandler,
  OnTransactionHandler,
} from '@metamask/snaps-types';
import { copyable, divider, heading, panel, text } from '@metamask/snaps-ui';

const TX_RISK_API_URL = 'http://localhost:8000/tx-scan';

type RiskFactor = {
  id?: string;
  domain?: string;
  severity?: string;
  title?: string;
  description?: string;
  score?: number;
};

type AssetImpact = {
  type?: string;
  asset?: {
    chainId?: string;
    address?: string | null;
    symbol?: string;
  };
  amount?: {
    formatted?: string;
    isUnlimited?: boolean;
  };
  from?: string;
  to?: string;
  spender?: string;
  operator?: string;
};

type TxRiskResponse = {
  schemaVersion?: string;
  inputRef?: string;
  verdict?: {
    riskLevel?: string;
    score?: number;
    confidence?: string;
    recommendedAction?: string;
  };
  summary?: string;
  recommendation?: string;
  intent?: {
    category?: string;
    description?: string;
    decodedFunction?: string | null;
  };
  assetImpact?: AssetImpact[];
  riskFactors?: RiskFactor[];
  evidence?: {
    limitations?: string[];
    evidenceQuality?: {
      mode?: string;
      decisionReliability?: string;
      minimumEvidenceMet?: boolean;
    };
  };
};

const scanTransactionRisk = async (payload: {
  chainId: string;
  transactionOrigin: string;
  transaction: unknown;
}): Promise<TxRiskResponse> => {
  const response = await fetch(TX_RISK_API_URL, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`TX risk API returned ${response.status}.`);
  }

  return (await response.json()) as TxRiskResponse;
};

export const onRpcRequest: OnRpcRequestHandler = async ({ origin, request }) => {
  switch (request.method) {
    case 'hello': {
      const approved = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'Confirmation',
          content: panel([
            heading('Hello from TxRiskAgent'),
            text(`Request origin: **${origin}**`),
            text('This dialog is rendered inside MetaMask by the Snap.'),
          ]),
        },
      });

      return {
        approved,
        message: approved
          ? 'User approved the Snap dialog.'
          : 'User rejected the Snap dialog.',
        timestamp: new Date().toISOString(),
      };
    }

    default:
      throw new Error(`Unsupported method: ${request.method}`);
  }
};

export const onTransaction: OnTransactionHandler = async ({
  chainId,
  transaction,
  transactionOrigin,
}) => {
  const payload = {
    chainId,
    transactionOrigin: transactionOrigin ?? 'unknown',
    transaction,
  };

  try {
    const risk = await scanTransactionRisk(payload);
    const riskLevel = risk.verdict?.riskLevel ?? 'UNKNOWN';
    const recommendedAction = risk.verdict?.recommendedAction ?? 'UNKNOWN';
    const isCriticalRisk =
      riskLevel === 'CRITICAL' || recommendedAction === 'REJECT';
    const isHighRisk = riskLevel === 'HIGH';
    const insightContent = buildInsightContent(risk);

    if (isCriticalRisk) {
      return {
        content: panel([heading('Critical Risk'), ...insightContent]),
        severity: 'critical',
      };
    }

    if (isHighRisk) {
      return {
        content: panel([heading('High Risk'), ...insightContent]),
      };
    }

    return {
      content: panel([heading('Transaction Risk Scan'), ...insightContent]),
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';

    return {
      content: panel([
        heading('Transaction Risk Scan'),
        text('TxRiskAgent scan failed, so this transaction could not be verified.'),
        text(message),
        copyable(JSON.stringify(payload, null, 2)),
      ]),
    };
  }
};

const buildInsightContent = (risk: TxRiskResponse) => [
  text(formatVerdictLine(risk)),
  text(risk.summary ?? 'TxRiskAgent did not return a summary.'),
  text(
    `**Recommended action:** ${
      risk.verdict?.recommendedAction ?? 'UNKNOWN'
    }`,
  ),
  text(risk.recommendation ?? 'No recommendation returned.'),
  divider(),
  heading('What This Transaction Does'),
  text(formatIntent(risk)),
  text(formatAssetImpact(risk.assetImpact ?? [])),
  divider(),
  heading('Why It Was Flagged'),
  text(formatRiskFactors(risk.riskFactors ?? [])),
  divider(),
  heading('Technical Details'),
  text(formatTechnicalDetails(risk)),
  copyable(JSON.stringify(risk, null, 2)),
];

const formatVerdictLine = (risk: TxRiskResponse) => {
  const verdict = risk.verdict;

  return `**Verdict:** ${verdict?.riskLevel ?? 'UNKNOWN'} | **Score:** ${
    verdict?.score ?? 'UNKNOWN'
  } | **Confidence:** ${verdict?.confidence ?? 'UNKNOWN'}`;
};

const formatIntent = (risk: TxRiskResponse) => {
  const category = risk.intent?.category ?? 'UNKNOWN';
  const description = risk.intent?.description ?? 'No intent description returned.';
  const decodedFunction = risk.intent?.decodedFunction;

  if (!decodedFunction) {
    return `**Intent:** ${category}\n${description}`;
  }

  return `**Intent:** ${category}\n**Function:** ${decodedFunction}\n${description}`;
};

const formatAssetImpact = (impacts: AssetImpact[]) => {
  const primaryImpacts = impacts.slice(0, 2);

  if (primaryImpacts.length === 0) {
    return '[]';
  }

  return primaryImpacts
    .map((impact) => {
      const asset = impact.asset?.symbol ?? impact.asset?.address ?? 'asset';
      const amount = impact.amount?.formatted ?? 'unknown amount';
      const counterparty =
        impact.to ?? impact.spender ?? impact.operator ?? 'unknown counterparty';
      const unlimited = impact.amount?.isUnlimited ? ' unlimited' : '';

      return `- ${impact.type ?? 'UNKNOWN'}: ${amount}${unlimited} ${asset} -> ${shortenAddress(
        counterparty,
      )}`;
    })
    .join('\n');
};

const formatRiskFactors = (factors: RiskFactor[]) => {
  const primaryFactors = factors.slice(0, 3);

  if (primaryFactors.length === 0) {
    return 'No risk factors were returned.';
  }

  return primaryFactors.map(formatRiskFactor).join('\n');
};

const formatRiskFactor = (factor: RiskFactor) => {
  const severity = factor.severity ?? 'UNKNOWN';
  const title = factor.title ?? factor.id ?? 'Risk factor';
  const description = factor.description ? `: ${factor.description}` : '';

  return `- **${severity}** (${factor.domain ?? 'unknown'}, score ${
    factor.score ?? 'UNKNOWN'
  }): ${title}${description}`;
};

const formatTechnicalDetails = (risk: TxRiskResponse) => {
  const quality = risk.evidence?.evidenceQuality;
  const limitations = risk.evidence?.limitations ?? [];
  const details = [
    `schemaVersion: ${risk.schemaVersion ?? 'unknown'}`,
    `inputRef: ${shortenInputRef(risk.inputRef)}`,
    `evidence mode: ${quality?.mode ?? 'UNKNOWN'}`,
    `reliability: ${quality?.decisionReliability ?? 'UNKNOWN'}`,
  ];

  if (limitations.length > 0) {
    details.push(`limitations: ${limitations.slice(0, 2).join(' | ')}`);
  }

  return details.join('\n');
};

const shortenAddress = (value: string) => {
  if (!/^0x[a-fA-F0-9]{40}$/.test(value)) {
    return value;
  }

  return `${value.slice(0, 6)}...${value.slice(-4)}`;
};

const shortenInputRef = (value?: string) => {
  if (!value) {
    return 'not returned';
  }

  if (value.length <= 28) {
    return value;
  }

  return `${value.slice(0, 18)}...${value.slice(-8)}`;
};
