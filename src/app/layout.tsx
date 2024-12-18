import './globals.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Ethereum Message Encryption',
  description: 'Secure message encryption using Ethereum wallets',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-background font-sans antialiased">
        {children}
      </body>
    </html>
  )
}
