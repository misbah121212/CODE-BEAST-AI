import type { NextConfig } from "next";

const isVercel = process.env.VERCEL === "1";

const nextConfig: NextConfig = {
  /* config options here */
  ...(isVercel ? {} : {
    output: "export",
    basePath: "/CODE-BEAST-AI",
    trailingSlash: true,
  }),
  images: {
    unoptimized: true,
  },
  allowedDevOrigins: ['10.99.148.224'],
};

export default nextConfig;
