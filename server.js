const express = require('express');
const app = express();

// Middleware to parse JSON
app.use(express.json());

// API Endpoint: Welcome route
app.get('/', (req, res) => {
    res.send('Welcome to your API server!');
});

// API Endpoint: Return sample data
app.get('/api/data', (req, res) => {
    res.json({ message: 'Hello, this is your API data!', data: [42, 'AWS', true] });
});

// API Endpoint: Accept POST requests
app.post('/api/submit', (req, res) => {
    const userData = req.body;
    res.json({ message: 'Data received!', receivedData: userData });
});

// Start the server
const PORT = 3001;
app.listen(PORT, () => {
    console.log(`API server running at http://localhost:${PORT}`);
});

//Error handling
process.on('uncaughtException', function (err) {
    console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', function (reason, promise) {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});