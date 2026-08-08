/** @type {import('next').NextConfig} */
const nextConfig = {
  // Type errors previously did not fail the build. For an app whose job is
  // encrypting other people's files, a type error reaching production is not an
  // acceptable default.
  //
  // Next 16 removed the `eslint` key along with `next lint`, so linting is no
  // longer part of `next build`. It still gates every build via `pnpm verify`,
  // which CI runs before the image is built.
  typescript: {
    ignoreBuildErrors: false,
  },
  images: {
    unoptimized: true,
  },
  // Trim the image: only the files the server actually needs get copied.
  output: "standalone",
  poweredByHeader: false,
  // Pin the build ID to the commit rather than a random string, so two builds
  // of the same source produce the same asset paths. This is what lets the
  // integrity monitor compare what is actually served against what CI built.
  generateBuildId: async () => process.env.BUILD_SHA || "development",
}

export default nextConfig
