import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "voter_stark WASM bench",
  description: "Client-side Plonky3 proving benchmark",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
