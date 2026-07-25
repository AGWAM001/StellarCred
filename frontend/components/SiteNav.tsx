"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { IconBook2, IconCode, IconMenu2, IconX } from "@tabler/icons-react";

const LINKS = [
  { href: "/holder",   label: "Wallet" },
  { href: "/verify",   label: "Verify" },
  { href: "/issuer",   label: "Issuer" },
  { href: "/apps",     label: "Apps" },
];

function ShieldIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden>
      <path
        d="M11 2.5L4 5.5v5.25c0 4.97 3.253 9.63 7 10.75 3.747-1.12 7-5.78 7-10.75V5.5L11 2.5z"
        fill="rgba(62,207,142,0.12)"
        stroke="#3ecf8e"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M8 11.2l2.1 2.1 4-4"
        stroke="#3ecf8e"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function SiteNav() {
  const pathname = usePathname();
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => setMenuOpen(false), [pathname]);

  return (
    <header className={`nav${menuOpen ? " menu-open" : ""}`}>
      <div className="nav-inner">
        <Link href="/" className="brand">
          <span className="brand-icon">
            <ShieldIcon />
          </span>
          StellarCred
        </Link>

        <button
          type="button"
          className="nav-toggle"
          aria-label="Toggle menu"
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen((o) => !o)}
        >
          {menuOpen ? <IconX size={18} stroke={1.8} /> : <IconMenu2 size={18} stroke={1.8} />}
        </button>

        <nav className="nav-links">
          {LINKS.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={pathname.startsWith(l.href) ? "active" : undefined}
            >
              {l.label}
            </Link>
          ))}
        </nav>

        <div className="nav-right">
          <Link
            href="/docs"
            className={`seg-link${pathname.startsWith("/docs") ? " active" : ""}`}
          >
            <IconBook2 size={14} stroke={1.8} />
            Docs
          </Link>
          <Link
            href="/developers"
            className={`seg-link${pathname.startsWith("/developers") ? " active" : ""}`}
          >
            <IconCode size={14} stroke={1.8} />
            Developers
          </Link>
        </div>
      </div>
    </header>
  );
}
