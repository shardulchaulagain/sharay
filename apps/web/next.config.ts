import type { NextConfig } from "next";

const config: NextConfig = {
  output: "export",
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  experimental: { webpackBuildWorker: false },
  images: { unoptimized: true },
};

export default config;
