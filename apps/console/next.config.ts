import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@precedent/contracts", "@precedent/events"],
};

export default nextConfig;
