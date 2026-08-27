import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  root: "ui",
  plugins: [react(), tailwindcss()],
  define: { "process.env.NODE_ENV": JSON.stringify("production") },
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "ui"),
    },
  },
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/ui"),
    emptyOutDir: true,
    cssCodeSplit: false,
    lib: {
      entry: path.resolve(import.meta.dirname, "ui/main.tsx"),
      formats: ["es"],
      fileName: () => "auth.js",
    },
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) => assetInfo.names.some((name) => name.endsWith(".css")) ? "style.css" : "[name][extname]",
      },
    },
  },
});
