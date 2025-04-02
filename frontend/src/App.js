import React, { useState } from "react";
import ScanForm from "./components/ScanForm";
import ScanResults from "./components/ScanResults";
import { Container, Typography, Box, Paper } from "@mui/material";

const App = () => {
  const [results, setResults] = useState(null);

  const handleScanComplete = (data) => {
    setResults(data);
  };

  return (
    <Container maxWidth="md" style={{ marginTop: "2rem" }}>
      <Paper elevation={3} style={{ padding: "2rem" }}>
        <Typography variant="h3" align="center" gutterBottom>
          Scanner de Vulnérabilités
        </Typography>
        <Box marginBottom={4}>
          <ScanForm onScanComplete={handleScanComplete} />
        </Box>
        <ScanResults results={results} />
      </Paper>
    </Container>
  );
};

export default App;