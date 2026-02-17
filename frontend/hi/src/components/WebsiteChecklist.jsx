import { useState } from "react";

export default function WebsiteChecklist() {
  const [open, setOpen] = useState(false);

  const items = [
    "HTTPS enabled with a valid SSL certificate (secure padlock in browser)",
    "Clear and professional design without suspicious pop-ups or redirects",
    "Proper login security (strong password rules, OTP or multi-factor authentication)",
    "Verified domain name (no spelling mistakes or fake look-alike URLs)",
    "Visible privacy policy and contact information",
    "No unexpected file downloads or malicious warnings from the browser",
    "Forms request only necessary information (no excessive personal data)",
    "Security indicators aligned with best practices from OWASP"
  ];

  return (
    <div className="border rounded p-4 bg-sky-50 mt-4">
      <button
        onClick={() => setOpen(!open)}
        className="font-semibold text-sky-700 flex items-center gap-1"
      >
        {open ? "▾" : "▸"} Website Safety Checklist (UI Level)
      </button>

      {open && (
        <ul className="mt-3 space-y-1">
          {items.map((text, i) => (
            <li key={i} className="flex items-start gap-2">
              <span className="text-green-600">✅</span>
              <span>{text}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}