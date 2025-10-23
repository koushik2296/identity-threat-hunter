/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  // Expose the ingestor endpoint to the app (used by pages/api/trigger.js)
  env: {
    INGEST_URL: "https://ith-ingestor-1054075376433.us-central1.run.app/ingest"
  }
};

module.exports = nextConfig;
