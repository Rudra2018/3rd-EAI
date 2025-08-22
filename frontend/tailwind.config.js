/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Halodoc-like palette (tasteful approximation—not official brand)
        hd: {
          bg: "#0b1220",
          card: "#0f172a",
          border: "#1f2937",
          text: "#e2e8f0",
          mut: "#94a3b8",
          accent: "#ef4444", // red
          grad1: "#ef4444",
          grad2: "#f97316",
        },
      },
      boxShadow: {
        card: "0 10px 30px rgba(0,0,0,0.25)",
      },
      borderRadius: {
        xl2: "1rem",
      },
    },
  },
  plugins: [],
};

