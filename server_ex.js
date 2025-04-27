const express = require('express');
const app = express();
const port = 3001;

// Middleware to parse JSON requests
app.use(express.json());

// Example Data (you can later replace this with a database or data store)
let users = [
  { id: 1, name: 'John', age: 30 },
  { id: 2, name: 'Jane', age: 24 },
  { id: 3, name: 'Mike', age: 43 },
  { id: 4, name: 'Ronie', age: 55 },
  { id: 5, name: 'Harry', age: 31 },
  { id: 6, name: 'Anna', age: 27 },
  { id: 7, name: 'Claudia', age: 29 }
];

// Home route
app.get('/', (req, res) => {
  res.send('Hello from API!');
});

// GET route: Get all users
app.get('/api/users', (req, res) => {
  res.json(users);
});

// GET route: Get a single user by ID
app.get('/api/users/:id', (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).send('User not found');
  res.json(user);
});

// POST route: Create a new user
app.post('/api/users', (req, res) => {
  const newUser = {
    id: users.length + 1,
    name: req.body.name,
    age: req.body.age
  };
  users.push(newUser);
  res.status(201).json(newUser);
});

// PUT route: Update a user by ID
app.put('/api/users/:id', (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).send('User not found');

  user.name = req.body.name;
  user.age = req.body.age;
  res.json(user);
});

// DELETE route: Delete a user by ID
app.delete('/api/users/:id', (req, res) => {
  const userIndex = users.findIndex(u => u.id === parseInt(req.params.id));
  if (userIndex === -1) return res.status(404).send('User not found');

  const deletedUser = users.splice(userIndex, 1);
  res.json(deletedUser);
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
