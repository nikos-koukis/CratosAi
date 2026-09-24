import type { ComponentProps, ReactNode } from 'react'

// Presentational building blocks, usable from server and client components.

function cx(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(' ')
}

const BUTTON = {
  primary: 'bg-indigo-600 text-white hover:bg-indigo-500 disabled:bg-indigo-400',
  secondary:
    'bg-white text-zinc-900 ring-1 ring-zinc-300 hover:bg-zinc-50 dark:bg-zinc-900 dark:text-zinc-100 dark:ring-zinc-700 dark:hover:bg-zinc-800',
  danger: 'bg-red-600 text-white hover:bg-red-500 disabled:bg-red-400',
  ghost: 'text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-zinc-800',
} as const

export function buttonClass(variant: keyof typeof BUTTON = 'primary', className?: string): string {
  return cx(
    'inline-flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors',
    'disabled:cursor-not-allowed disabled:opacity-70',
    BUTTON[variant],
    className,
  )
}

export function Button({
  variant = 'primary',
  className,
  type = 'button',
  ...props
}: ComponentProps<'button'> & { variant?: keyof typeof BUTTON }) {
  return <button type={type} className={buttonClass(variant, className)} {...props} />
}

const FIELD =
  'block w-full rounded-md border-0 bg-white px-3 py-2 text-sm text-zinc-900 ring-1 ring-zinc-300 ring-inset ' +
  'placeholder:text-zinc-400 focus:ring-2 focus:ring-indigo-500 dark:bg-zinc-900 dark:text-zinc-100 dark:ring-zinc-700'

export function Input({ className, ...props }: ComponentProps<'input'>) {
  return <input className={cx(FIELD, className)} {...props} />
}

export function Select({ className, ...props }: ComponentProps<'select'>) {
  return <select className={cx(FIELD, className)} {...props} />
}

export function Field({
  label,
  htmlFor,
  hint,
  children,
}: {
  label: string
  htmlFor: string
  hint?: ReactNode
  children: ReactNode
}) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="block text-sm font-medium text-zinc-800 dark:text-zinc-200">
        {label}
      </label>
      {children}
      {hint && <p className="text-xs text-zinc-500 dark:text-zinc-400">{hint}</p>}
    </div>
  )
}

export function Card({
  title,
  description,
  actions,
  children,
}: {
  title?: ReactNode
  description?: ReactNode
  actions?: ReactNode
  children?: ReactNode
}) {
  return (
    <section className="rounded-lg bg-white p-5 shadow-sm ring-1 ring-zinc-200 dark:bg-zinc-900 dark:ring-zinc-800">
      {(title || actions) && (
        <header className="mb-4 flex items-start justify-between gap-4">
          <div>
            {title && <h2 className="text-base font-semibold">{title}</h2>}
            {description && <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">{description}</p>}
          </div>
          {actions}
        </header>
      )}
      {children}
    </section>
  )
}

const ALERT = {
  error: 'bg-red-50 text-red-800 ring-red-200 dark:bg-red-950/50 dark:text-red-200 dark:ring-red-900',
  info: 'bg-indigo-50 text-indigo-900 ring-indigo-200 dark:bg-indigo-950/50 dark:text-indigo-100 dark:ring-indigo-900',
  success:
    'bg-emerald-50 text-emerald-900 ring-emerald-200 dark:bg-emerald-950/50 dark:text-emerald-100 dark:ring-emerald-900',
  warning:
    'bg-amber-50 text-amber-900 ring-amber-200 dark:bg-amber-950/50 dark:text-amber-100 dark:ring-amber-900',
} as const

export function Alert({ kind = 'info', children }: { kind?: keyof typeof ALERT; children: ReactNode }) {
  return (
    <div
      role={kind === 'error' ? 'alert' : 'status'}
      className={cx('rounded-md px-3 py-2 text-sm ring-1', ALERT[kind])}
    >
      {children}
    </div>
  )
}

const BADGE = {
  neutral: 'bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300',
  good: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-200',
  bad: 'bg-red-100 text-red-800 dark:bg-red-900/60 dark:text-red-200',
  accent: 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900/60 dark:text-indigo-200',
} as const

export function Badge({ tone = 'neutral', children }: { tone?: keyof typeof BADGE; children: ReactNode }) {
  return <span className={cx('rounded px-1.5 py-0.5 text-xs font-medium', BADGE[tone])}>{children}</span>
}

export function PageHeader({ title, description }: { title: string; description?: ReactNode }) {
  return (
    <header className="mb-6">
      <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
      {description && (
        <p className="mt-1 max-w-2xl text-sm text-zinc-600 dark:text-zinc-400">{description}</p>
      )}
    </header>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-sm text-zinc-500 dark:text-zinc-400">{children}</p>
}
