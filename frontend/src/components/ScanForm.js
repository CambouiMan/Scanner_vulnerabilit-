import React, { useState } from "react";
import axios from "axios";

const ScanForm = ({ onScanComplete }) => {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    try {
      const response = await axios.post("http://localhost:8000/scan/", { url });
      onScanComplete(response.data); // Appelle la fonction parent pour afficher les résultats
    } catch (err) {
      setError("Erreur lors du scan. Vérifiez l'URL et réessayez.");
    }
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Entrez une URL"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button type="submit">Scanner</button>
      </form>
      {error && <p style={{ color: "red" }}>{error}</p>}
    </div>
  );
};

export default ScanForm;