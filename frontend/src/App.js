import React, { useState } from "react";
import ScanForm from "./components/ScanForm";
import ScanResults from "./components/ScanResults";

const App = () => {
  const [results, setResults] = useState(null);

  const handleScanComplete = (data) => {
    setResults(data);
  };

  return (
    <div>
      <h1>Scanner de Vulnérabilités</h1>
      <ScanForm onScanComplete={handleScanComplete} />
      <ScanResults results={results} />
    </div>
  );
};

export default App;