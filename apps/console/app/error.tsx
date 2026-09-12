"use client";

export default function ConsoleError({
  reset,
}: {
  error: Error;
  reset: () => void;
}) {
  return (
    <main className="console-shell">
      <section className="connection-banner" role="alert">
        <h1>The console could not display this state.</h1>
        <p>
          The response services run separately. Reload the console to reconnect
          and inspect their latest state.
        </p>
        <button onClick={reset}>Retry console</button>
      </section>
    </main>
  );
}
