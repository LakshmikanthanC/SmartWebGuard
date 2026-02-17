export default function Recommendations({ steps }) {
  if (!steps || steps.length === 0) return null;
  return (
    <div className="border rounded p-4 bg-green-50 mt-4">
      <h2 className="font-semibold mb-2">Recommended Actions</h2>
      <ol className="list-decimal list-inside space-y-1">
        {steps.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ol>
    </div>
  );
}
