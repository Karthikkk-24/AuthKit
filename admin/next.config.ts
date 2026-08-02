import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Required for the multi-stage Dockerfile admin target (#36)
  output: "standalone",
};

export default nextConfig;
