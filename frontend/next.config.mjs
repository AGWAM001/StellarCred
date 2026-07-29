import { createRequire } from "module";

const require = createRequire(import.meta.url);
const bufferPath = require.resolve("buffer/");
const processPath = require.resolve("process/browser");

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,

  // The /api/issue route runs Noir server-side to compute the Poseidon
  // commitment. Keep these out of the server bundle so Node require()s them
  // from node_modules and resolves their CJS/"nodejs" entry points, which read
  // the WASM from disk with fs. If bundled, webpack picks the "web" build that
  // fetch()es the WASM via a /_next/... URL, which has no base on the server
  // ("Failed to parse URL from /_next/static/media/...wasm").
  experimental: {
    serverComponentsExternalPackages: [
      "@noir-lang/noir_js",
      "@noir-lang/acvm_js",
      "@noir-lang/noirc_abi",
    ],
  },

  // Noir + Barretenberg (bb.js) prove in WASM in the browser. They expect Node
  // globals (Buffer/process) and load WASM modules; these settings make the
  // client bundle work without server-side polyfills.
  webpack: (config, { webpack, isServer }) => {
    config.experiments = { ...config.experiments, asyncWebAssembly: true };

    // lib/wallet.ts's WalletConnectModule pulls in @walletconnect/sign-client
    // -> @walletconnect/logger -> pino, which conditionally requires
    // pino-pretty (a dev-only pretty-printing transport, never used in the
    // browser bundle we ship). It's not a dependency here, so webpack can't
    // statically resolve it — aliasing it to false is pino's own documented
    // fix for bundlers (https://github.com/pinojs/pino/blob/main/docs/bundling.md).
    config.resolve.alias = { ...config.resolve.alias, "pino-pretty": false };

    // Buffer/process polyfills are only needed in the browser bundle.
    // Applying ProvidePlugin on the server replaces Node's real `process`
    // with `process/browser` (env: {}), which hides server-only env vars
    // like ISSUER_PRIVATE_KEY even after they are set in .env.local.
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        buffer: bufferPath,
        process: processPath,
      };
      config.plugins.push(
        new webpack.ProvidePlugin({
          Buffer: ["buffer", "Buffer"],
          process: processPath,
        }),
      );
    }

    return config;
  },

  // NOTE: We intentionally do NOT set Cross-Origin-Opener/Embedder-Policy.
  // Those headers enable SharedArrayBuffer (crossOriginIsolated), which makes
  // bb.js take its *multithreaded* path. That path spawns a Web Worker from
  // @aztec/bb.js's prebuilt main.worker.js bundle via `new Worker(new URL(...))`.
  // Next.js's webpack re-wraps that already-bundled file and corrupts its inner
  // module runtime, throwing "Object.defineProperty called on non-object" the
  // moment you generate a proof. Without these headers, getSharedMemoryAvailable()
  // is false, so bb.js runs single-threaded: it only loads barretenberg.js (a
  // trivial one-line module exporting the wasm as a data URI) and never touches
  // the worker. Slower proving, but it actually runs. See lib/proof.ts.
  //
  // The security headers below are separate from COOP/COEP and safe to add.
  // 'wasm-unsafe-eval' in script-src is required for WASM instantiation and
  // is unrelated to cross-origin isolation, so it does not re-enable the
  // multithreaded path above.
  async headers() {
    // lib/wallet.ts only registers WalletConnectModule (and only the app ever
    // opens its relay/verify/explorer traffic) when this is set — keep the CSP
    // minimally permissive for deployments that leave WalletConnect disabled.
    const walletConnectEnabled = Boolean(process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID);

    const csp = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      // Wallet icons for the Stellar Wallets Kit picker: stellar.creit.tech hosts
      // Albedo/Freighter/xBull/Rabet/Lobstr/Hana/Klever/WalletConnect's, storage.herewallet.app
      // hosts HOT Wallet's — needed for every wallet the kit shows, not just WalletConnect,
      // so these two stay unconditional. explorer-api.walletconnect.com is WalletConnect's
      // own wallet list, shown only if its QR pairing screen is opened.
      // Verified against the actual requests the picker modal makes in a real browser
      // (next build && next start), not just package source greps.
      `img-src 'self' data: https://stellar.creit.tech https://storage.herewallet.app${
        walletConnectEnabled ? " https://explorer-api.walletconnect.com" : ""
      }`,
      // contracts.ts ("use client") calls getAccount / prepareTransaction /
      // sendTransaction against the Soroban RPC from the browser — must be
      // allowed here or proof submission and on-chain verification break.
      // The relay/explorer/verify entries are required by lib/wallet.ts's
      // WalletConnectModule — hardcoded by @walletconnect/core and
      // @walletconnect/modal-core, not configurable via env.
      `connect-src 'self' https://soroban-testnet.stellar.org https://soroban-mainnet.stellar.org${
        walletConnectEnabled
          ? " wss://relay.walletconnect.com wss://relay.walletconnect.org https://explorer-api.walletconnect.com https://verify.walletconnect.com https://verify.walletconnect.org"
          : ""
      }${process.env.NEXT_PUBLIC_RPC_URL ? " " + process.env.NEXT_PUBLIC_RPC_URL : ""}`,
    ];
    if (walletConnectEnabled) {
      // verify.walletconnect.{com,org} is WalletConnect's domain-verification
      // iframe (loaded by @walletconnect/sign-client); without this it's
      // silently blocked and WalletConnect connect attempts hang.
      csp.push("frame-src 'self' https://verify.walletconnect.com https://verify.walletconnect.org");
    }

    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: csp.join("; ") + ";" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains",
          },
          { key: "X-Frame-Options", value: "DENY" },
        ],
      },
      {
        source: "/api/:path*",
        headers: [
          {
            key: "Access-Control-Allow-Origin",
            value: process.env.APP_ORIGIN || "http://localhost:3000",
          },
          { key: "Access-Control-Allow-Methods", value: "GET, POST, OPTIONS" },
          { key: "Access-Control-Allow-Headers", value: "Content-Type, Authorization" },
          { key: "Vary", value: "Origin" },
        ],
      },
    ];
  },
};

export default nextConfig;