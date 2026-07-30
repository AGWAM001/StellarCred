import { NextRequest, NextResponse } from "next/server";
import { logger, stripSensitiveFields, resolveRequestId } from "../../../lib/logger";
import { fetchPlaidBalance } from "../../../lib/plaid";

export async function GET(req: NextRequest) {
  const requestId = resolveRequestId(req.headers.get("x-request-id"));

  const sendResponse = (response: NextResponse) => {
    response.headers.set("x-request-id", requestId);
    return response;
  };

  logger.info(stripSensitiveFields({ event: "plaid_balance_request_received", requestId }));

  const result = await fetchPlaidBalance(requestId);

  if (!result.ok) {
    return sendResponse(
      NextResponse.json({ error: result.error, code: result.code }, { status: result.status }),
    );
  }

  return sendResponse(
    NextResponse.json(
      result.mock
        ? { balance: result.balance, mock: true }
        : { balance: result.balance, accounts: result.accounts },
    ),
  );
}
