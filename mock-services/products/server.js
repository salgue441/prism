const express = require('express');
const app = express();
const port = process.env.PORT || 8080;

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'products-service' });
});

app.get('/', (req, res) => {
  res.json({ server: 'products-service', service: 'products' });
});

app.listen(port, () => {
  console.log(`Products service running on port ${port}`);
});