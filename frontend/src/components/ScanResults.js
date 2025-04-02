import React from "react";

const ScanResults = ({ results }) => {
  if (!results) return null;

  return (
    <div>
      <h2>Résultats du Scan</h2>
      {results.map((result, index) => (
        <div key={index}>
          <p>Type: {result.type}</p>
          <p>URL: {result.url}</p>
          <p>Status: {result.status}</p>
          {result.payload && <p>Payload: {result.payload}</p>}
        </div>
      ))}
    </div>
  );
};

export default ScanResults;