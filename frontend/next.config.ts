import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  output: "export",
  basePath: "/CODE-BEAST-AI",
  images: {
    unoptimized: true,
  },
  allowedDevOrigins: ['10.99.148.224'],
};

export default nextConfig;
