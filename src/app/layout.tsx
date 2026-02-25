import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import SecurityOverlay from "@/components/SecurityOverlay";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Vibe Security Watchdog",
  description: "Next.js Security Watchdog — Geliştirme ortamı güvenlik nöbetçisi",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="tr">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
        {/* Security Overlay — sadece development ortamında render olur */}
        {process.env.NODE_ENV === 'development' && <SecurityOverlay />}
      </body>
    </html>
  );
}
