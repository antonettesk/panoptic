import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { CornerDownLeft, Search } from 'lucide-react';
import { useI18n } from '../i18n';
import { matchesQuery } from '../util';

export interface Command {
  id: string;
  label: string;
  hint?: string;
  icon?: ReactNode;
  run: () => void;
}

export function CommandPalette({ open, onClose, commands }: { open: boolean; onClose: () => void; commands: Command[] }) {
  const { t } = useI18n();
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const list = useMemo(() => commands.filter((c) => matchesQuery(q, c.label, c.hint, c.id)), [commands, q]);

  useEffect(() => {
    if (open) {
      setQ('');
      setIdx(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);
  useEffect(() => setIdx(0), [q]);

  if (!open) return null;
  const run = (c: Command | undefined) => {
    if (!c) return;
    onClose();
    c.run();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/40 p-4 pt-[12vh] backdrop-blur-sm" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-label={t('palette.hint')} className="card w-full max-w-xl animate-fade-in overflow-hidden shadow-pop" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search size={16} className="text-subtle" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={t('palette.placeholder')}
            className="h-12 flex-1 bg-transparent text-[14px] outline-none placeholder:text-subtle"
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setIdx((i) => Math.min(list.length - 1, i + 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setIdx((i) => Math.max(0, i - 1));
              } else if (e.key === 'Enter') {
                run(list[idx]);
              } else if (e.key === 'Escape') {
                onClose();
              }
            }}
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
          />
          <kbd className="kbd">Esc</kbd>
        </div>
        <ul id="palette-list" role="listbox" className="max-h-[50vh] overflow-auto p-1.5">
          {list.length === 0 && <li className="px-3 py-6 text-center text-[13px] text-muted">{t('palette.empty')}</li>}
          {list.map((c, i) => (
            <li key={c.id} role="option" aria-selected={i === idx}>
              <button onMouseEnter={() => setIdx(i)} onClick={() => run(c)} className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-start text-[13px] ${i === idx ? 'bg-brand/10 text-fg' : 'text-muted'}`}>
                <span className={i === idx ? 'text-brand' : 'text-subtle'}>{c.icon}</span>
                <span className="flex-1">{c.label}</span>
                {c.hint && <span className="text-[11px] text-subtle">{c.hint}</span>}
                {i === idx && <CornerDownLeft size={13} className="text-subtle" />}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
