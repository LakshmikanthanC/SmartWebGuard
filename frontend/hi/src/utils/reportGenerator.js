// utils/reportGenerator.js
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import * as XLSX from "xlsx";               // we’ll use this for Excel

// ---------- PDF ----------
export async function generatePDF(scan) {
  /* scan is exactly the 'result' object you keep in state */

  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const left = 40;                 // left margin

  // Header
  doc.setFontSize(20);
  doc.text("URL Safety Scan Report", left, 50);

  // Basic facts
  doc.setFontSize(11);
  const lines = [
    `URL           :  ${scan.url}`,
    `Overall verdict :  ${scan.safe ? "SAFE ✅" : "UNSAFE 🚨"}`,
    `Risk score      :  ${scan.riskScore} / 100  (${scan.riskLevel})`,
    `Scan type       :  ${scan.scanType}`,
    `Scanned on      :  ${new Date(scan.timestamp).toLocaleString()}`,
  ];
  lines.forEach((l, idx) => doc.text(l, left, 80 + idx * 18));

  // Findings table
  if (scan.findings?.length) {
    autoTable(doc, {
      startY: 80 + lines.length * 18 + 20,
      head: [["Severity", "Name", "Category", "Description"]],
      body: scan.findings.map((f) => [
        f.severity,
        f.name,
        f.category,
        f.description,
      ]),
      styles: { fontSize: 8, cellWidth: "wrap" },
      headStyles: { fillColor: [0, 122, 204] },
    });
  }

  // footer (page number)
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(9);
    doc.text(
      `Page ${i} of ${pageCount}`,
      doc.internal.pageSize.getWidth() - 60,
      doc.internal.pageSize.getHeight() - 20
    );
  }

  // trigger download
  doc.save(`url-scan-${Date.now()}.pdf`);
}

// ---------- Excel ----------
export async function generateExcel(scan) {
  const wb = XLSX.utils.book_new();

  // Overview sheet
  const overview = [
    ["URL", scan.url],
    ["Verdict", scan.safe ? "SAFE" : "UNSAFE"],
    ["Risk score", scan.riskScore],
    ["Risk level", scan.riskLevel],
    ["Scan type", scan.scanType],
    ["Scanned on", new Date(scan.timestamp).toLocaleString()],
  ];
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(overview), "Overview");

  // Findings sheet (if any)
  if (scan.findings?.length) {
    const findings = scan.findings.map((f) => ({
      Severity: f.severity,
      Name: f.name,
      Category: f.category,
      Description: f.description,
      "Risk points": f.risk_points,
    }));
    XLSX.utils.book_append_sheet(
      wb,
      XLSX.utils.json_to_sheet(findings),
      "Findings"
    );
  }

  XLSX.writeFile(wb, `url-scan-${Date.now()}.xlsx`);
}