import { useRef, useState } from "react";
import { api, type TraceSummary } from "../api";

export function Upload({ onUploaded }: { onUploaded: (t: TraceSummary) => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send(files: FileList | null) {
    if (!files?.length) return;
    setBusy(true);
    setError(null);
    try {
      for (const file of Array.from(files)) {
        onUploaded(await api.upload(file));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  }

  return (
    <>
      <div
        className={`drop${over ? " over" : ""}`}
        onClick={() => input.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setOver(true); }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => { e.preventDefault(); setOver(false); void send(e.dataTransfer.files); }}
      >
        {busy ? (
          <strong>Analysing…</strong>
        ) : (
          <>
            <strong>Drop a trace here</strong>
            pcap, pcapng, a text SIP log, or an OCOM message-flow export
          </>
        )}
      </div>
      <input
        ref={input}
        type="file"
        multiple
        hidden
        accept=".pcap,.pcapng,.cap,.log,.txt,.html,.htm"
        onChange={(e) => void send(e.target.files)}
      />
      {error && <p className="error">{error}</p>}
    </>
  );
}
