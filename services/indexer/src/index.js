const config = require('./config');
const { createDb } = require('./db');
const { createApi } = require('./api');
const { runIngestLoop } = require('./ingest');

async function main() {
  const db = createDb();
  const app = createApi(db);

  app.listen(config.port, () => {
    console.log(`indexer API listening on port ${config.port}`);
  });

  runIngestLoop(db);
}

main().catch((err) => {
  console.error('fatal error starting indexer:', err);
  process.exit(1);
});
