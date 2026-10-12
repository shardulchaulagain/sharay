import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SHARAY · Security workspace",
  description: "Local, scope-controlled security assessments.",
  robots: { index: false, follow: false },
};

export default function Layout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
