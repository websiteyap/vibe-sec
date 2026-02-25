import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  webpack: (config, { dev, isServer }) => {
    // Sadece development + server-side'da watchdog'u başlat
    if (dev && isServer) {
      const path = require("path");
      const { VibeSecurityWebpackPlugin } = require("./src/security-watchdog/index");
      config.plugins.push(new VibeSecurityWebpackPlugin(process.cwd()));
    }

    return config;
  },
};

export default nextConfig;
