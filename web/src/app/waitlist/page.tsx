"use client";

import { useState } from "react";

type State = "idle" | "submitting" | "success" | "error";

export default function WaitlistPage() {
  const [state, setState] = useState<State>("idle");
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const data = new FormData(form);
    const payload = {
      email: String(data.get("email") ?? ""),
      org: String(data.get("org") ?? ""),
      use_case: String(data.get("use_case") ?? ""),
      agent_stack: String(data.get("agent_stack") ?? ""),
    };

    setState("submitting");
    setError(null);
    try {
      const r = await fetch("/api/waitlist", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        throw new Error(body.message ?? `HTTP ${r.status}`);
      }
      setState("success");
      form.reset();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setState("error");
    }
  }

  return (
    <main className="mx-auto max-w-2xl px-6 py-16">
      <header className="mb-10">
        <p className="text-xs uppercase tracking-widest text-slate-400">
          Agent Exchange Protocol (AEX)
        </p>
        <h1 className="mt-2 text-4xl font-bold">Request an invite</h1>
        <p className="mt-3 text-slate-300">
          AEX is in alpha. We onboard a handful of teams each week so we can
          support every deploy directly — share what you&apos;re building and
          we&apos;ll reach out.
        </p>
      </header>

      {state === "success" ? (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-6 text-emerald-200">
          <p className="font-semibold">You&apos;re on the list.</p>
          <p className="mt-2 text-sm text-emerald-100/80">
            We&apos;ll send an onboarding email with your dev-tier API key
            within 5 business days. In the meantime, the Python SDK and
            self-hosted control plane are already usable — see the
            <a
              href="https://github.com/icaroholding/spize/tree/master/packages/sdk-python"
              className="underline underline-offset-2 ml-1"
            >
              repo
            </a>.
          </p>
        </div>
      ) : (
        <form onSubmit={onSubmit} className="space-y-5">
          <Field label="Email" name="email" type="email" required />
          <Field label="Organization" name="org" type="text" required />
          <Field
            label="What will the agents do with Spize?"
            name="use_case"
            as="textarea"
            required
            hint="e.g. 'agents draft financial reports and deliver them to our analysts as PDFs'"
          />
          <Field
            label="Agent runtime"
            name="agent_stack"
            type="text"
            hint="Claude, GPT, Cursor, custom Python, LangGraph …"
          />

          <button
            type="submit"
            disabled={state === "submitting"}
            className="w-full rounded-md bg-blue-500 px-4 py-3 font-medium text-white hover:bg-blue-400 disabled:opacity-60"
          >
            {state === "submitting" ? "Submitting…" : "Request invite"}
          </button>

          {error && (
            <p className="text-sm text-rose-300">Error: {error}</p>
          )}
        </form>
      )}

      <footer className="mt-16 text-sm text-slate-400">
        <p>Already a customer? Use the dashboard at <code>/dashboard</code>.</p>
      </footer>
    </main>
  );
}

type FieldProps = {
  label: string;
  name: string;
  type?: string;
  required?: boolean;
  hint?: string;
  as?: "textarea" | "input";
};

function Field({ label, name, type = "text", required, hint, as = "input" }: FieldProps) {
  const common =
    "mt-1 block w-full rounded-md border border-white/10 bg-black/30 px-3 py-2 text-sm outline-none focus:border-blue-400";
  return (
    <label className="block">
      <span className="text-sm text-slate-200">{label}</span>
      {as === "textarea" ? (
        <textarea name={name} required={required} rows={3} className={common} />
      ) : (
        <input name={name} type={type} required={required} className={common} />
      )}
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}
