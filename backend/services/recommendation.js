// helper – normalises a Suricata signature to a playbook key
function deriveKey(sig = "") {
  const s = sig.toLowerCase();
  if (s.includes("phish"))       return "phishing";
  if (s.includes("malware"))     return "malware_download";
  if (s.includes("drive-by"))    return "drive_by";
  if (s.includes("c2") || s.includes("command")) return "c2_callback";
  if (s.includes("cryptominer")) return "cryptominer";
  return "generic_url";
}

// map → explanation + numbered steps
const playbooks = {
  phishing: {
    explanation:
      "The requested URL is classified as a phishing site designed to steal credentials or personal data.",
    steps: [
      "Block the URL/domain on the organisation’s secure web gateway or firewall.",
      "Force-expire active sessions for users who accessed the link.",
      "Reset potentially compromised passwords and enable MFA.",
      "Report the phishing page to the hosting provider and anti-phishing feeds.",
      "Educate affected users on identifying phishing e-mails."
    ]
  },
  malware_download: {
    explanation:
      "The URL is hosting a known malicious binary or script that can infect the system.",
    steps: [
      "Quarantine or delete the downloaded file from affected hosts.",
      "Run a full antivirus/EDR scan on those hosts.",
      "Add the hash and URL to block lists (proxy, NGFW, EDR).",
      "Patch browsers and plugins to the latest versions.",
      "Review proxy logs to find additional downloads from the same host."
    ]
  },
  drive_by: {
    explanation:
      "The site is serving exploit-laden web pages that silently compromise browsers (drive-by download).",
    steps: [
      "Block the domain/IP on perimeter devices.",
      "Patch browsers, Java, Flash and related components immediately.",
      "Inspect the host for suspicious DLL injection or browser exploit artefacts.",
      "Consider implementing browser isolation for high-risk users.",
      "Submit the exploit kit samples to your threat-intel platform."
    ]
  },
  c2_callback: {
    explanation:
      "Outbound HTTP/S traffic matches a known Command-and-Control (C2) pattern.",
    steps: [
      "Isolate the host from the network to prevent lateral movement.",
      "Capture memory and disk images for forensic analysis.",
      "Block the C2 domain/IP on all egress points.",
      "Reset credentials used on the compromised host.",
      "Monitor for repeat callbacks or new IoCs."
    ]
  },
  cryptominer: {
    explanation:
      "Traffic indicates contact with a cryptomining pool – likely unauthorised cryptominer activity.",
    steps: [
      "Kill the mining process and remove associated binaries.",
      "Block outbound connections to mining pools.",
      "Patch the vulnerability used for initial compromise (commonly weak passwords or unpatched CMS).",
      "Audit system resource utilisation for lingering miners.",
      "Review cloud billing for unexpected spikes."
    ]
  },
  generic_url: {
    explanation:
      "The URL was flagged as potentially harmful, but no specific family could be identified.",
    steps: [
      "Block access to the URL/domain and place it under review.",
      "Submit the URL to sandbox or virus-scanning services (VirusTotal, Hybrid-Analysis).",
      "Check if any user downloaded content from the URL and scan those files.",
      "Add the domain to a watch list and monitor DNS queries.",
      "Inform users to avoid the site until further notice."
    ]
  }
};

export function getUrlRecommendation(signature) {
  const key = deriveKey(signature);
  return playbooks[key];
}