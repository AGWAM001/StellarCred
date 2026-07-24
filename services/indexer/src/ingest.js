const { rpc } = require('@stellar/stellar-sdk');
const config = require('./config');
const { parseEvent } = require('./decode');
const { extractInvocation, stringifyIfObject } = require('./tx');

function sleep(ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function parseRangeError(message) {
  const match = /ledger range:\s*(\d+)\s*-\s*(\d+)/.exec(message || '');
  if (!match) return null;
  return { low: parseInt(match[1], 10), high: parseInt(match[2], 10) };
}

async function fetchEventsBatch(server, startLedger) {
  const events = [];
  let cursor;
  let latestLedger = startLedger;

  while (true) {
    const params = {
      filters: [
        {
          type: 'contract',
          contractIds: [config.contractId],
        },
      ],
      limit: config.eventPageLimit,
    };
    if (cursor) {
      params.cursor = cursor;
    } else {
      params.startLedger = startLedger;
    }

    const response = await server.getEvents(params);
    latestLedger = response.latestLedger || latestLedger;

    if (!response.events || response.events.length === 0) break;
    for (const evt of response.events) events.push(evt);

    if (response.events.length < config.eventPageLimit) break;
    cursor = response.cursor;
    if (!cursor) break;
  }

  return { events: events, latestLedger: latestLedger };
}

async function enrichVerifiedEvents(server, parsedEvents) {
  const groups = new Map();
  for (const evt of parsedEvents) {
    if (!evt.needsEnrichment) continue;
    if (!groups.has(evt.txHash)) groups.set(evt.txHash, []);
    groups.get(evt.txHash).push(evt);
  }

  for (const entry of groups) {
    const txHash = entry[0];
    const group = entry[1];
    let txResult;
    try {
      txResult = await server.getTransaction(txHash);
    } catch (err) {
      console.error('failed to fetch tx ' + txHash + ': ' + err.message);
      continue;
    }

    if (!txResult || !txResult.envelopeXdr) {
      console.error('no envelope found for tx ' + txHash);
      continue;
    }

    let invocation;
    try {
      invocation = extractInvocation(txResult.envelopeXdr);
    } catch (err) {
      console.error('failed to parse invocation for tx ' + txHash + ': ' + err.message);
      continue;
    }

    if (!invocation) continue;

    if (invocation.functionName === 'submit_proof' && group.length === 1) {
      const holder = invocation.args[0];
      const issuerId = invocation.args[1];
      const credentialType = invocation.args[2];
      group[0].wallet = stringifyIfObject(holder);
      group[0].issuer = stringifyIfObject(issuerId);
      group[0].credentialType = stringifyIfObject(credentialType);
      continue;
    }

    if (invocation.functionName === 'submit_proofs_batch') {
      const holder = invocation.args[0];
      const submissions = invocation.args[1];
      const walletStr = stringifyIfObject(holder);
      const list = Array.isArray(submissions) ? submissions : [];
      group.forEach(function (evt, i) {
        const submission = list[i];
        if (!submission) {
          console.error('no matching submission for event ' + evt.eventId + ' in tx ' + txHash);
          return;
        }
        evt.wallet = walletStr;
        evt.credentialType = stringifyIfObject(submission.credential_type);
        evt.issuer = stringifyIfObject(submission.issuer_id);
      });
      continue;
    }

    console.error('unrecognized invocation "' + invocation.functionName + '" for tx ' + txHash);
  }
}

async function runIngestLoop(db) {
  if (!config.contractId) {
    console.error('PROOF_REGISTRY_CONTRACT_ID is not set; ingestion will not start.');
    return;
  }

  const server = new rpc.Server(config.rpcUrl, { allowHttp: config.rpcUrl.startsWith('http://') });

  while (true) {
    try {
      const lastLedger = await db.getLastLedger();
      const startLedger = Math.max(lastLedger + 1, config.startLedger || 1);

      const batch = await fetchEventsBatch(server, startLedger);
      const events = batch.events;
      const latestLedger = batch.latestLedger;

      const parsedEvents = events.map(parseEvent).filter(function (evt) {
        return evt !== null;
      });

      await enrichVerifiedEvents(server, parsedEvents);

      let stored = 0;
      for (const evt of parsedEvents) {
        if (!evt.wallet || !evt.credentialType) continue;
        await db.insertEvent(evt);
        stored += 1;
      }

      if (latestLedger && latestLedger > lastLedger) {
        await db.setLastLedger(latestLedger);
      }

      console.log('ingest cycle complete: found ' + events.length + ' raw events, stored ' + stored + ', last_ledger=' + latestLedger);
    } catch (err) {
      const range = parseRangeError(err.message);
      if (range) {
        console.log('clamping start ledger to retained range, jumping to ' + range.low);
        await db.setLastLedger(range.low - 1);
        continue;
      }
      console.error('ingest cycle failed: ' + err.message);
    }

    await sleep(config.pollIntervalMs);
  }
}

module.exports = { runIngestLoop: runIngestLoop };
