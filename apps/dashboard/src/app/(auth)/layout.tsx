export default function AuthLayout({ children }: LayoutProps<'/'>) {
  return (
    <main className="flex min-h-dvh items-center justify-center p-6">
      <div className="w-full max-w-md space-y-6">
        <p className="text-center text-2xl font-semibold tracking-tight">Jarvis</p>
        <div className="rounded-lg bg-white p-6 shadow-sm ring-1 ring-zinc-200 dark:bg-zinc-900 dark:ring-zinc-800">
          {children}
        </div>
      </div>
    </main>
  )
}
