const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 5500;
const SECRET_KEY = 'gersoniantero';

app.use(cors({
  origin: ['http://127.0.0.1:5500', 'http://localhost:5500']
}));

app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile('index.html', { root: 'public' });
});

let users = [
  { id: 1, username: 'admin', password: '$2a$10$...', role: 'admin' },
  { id: 2, username: 'alice', password: '$2a$10$...', role: 'user' }
];

let departments = [
  { id: 1, name: 'Engineering', description: 'Software team' },
  { id: 2, name: 'HR', description: 'Human Resources' }
];

let requests = [];

let employees = [
  {
    id: 1,
    employeeCode: 'EMP-001',
    name: 'Gerson Ian Tero',
    email: 'gerson@example.com',
    position: 'Developer',
    department: 'Engineering',
    hireDate: '2024-01-15'
  }
];

if (users[0].password.includes('$2a$')) {
  users[0].password = bcrypt.hashSync('admin123', 10);
  users[1].password = bcrypt.hashSync('user123', 10);
}

app.post('/api/register', async (req, res) => {
  const { username, password, role = 'user', firstName, lastName } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const existing = users.find(u => u.username === username);
  if (existing) {
    return res.status(409).json({ error: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: users.length + 1,
    username,
    password: hashedPassword,
    role,
    firstName: firstName || '',
    lastName: lastName || ''
  };

  users.push(newUser);
  res.status(201).json({
    message: 'User registered',
    username,
    role,
    firstName: newUser.firstName,
    lastName: newUser.lastName
  });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    SECRET_KEY,
    { expiresIn: '1h' }
  );

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName
    }
  });
});

app.get('/api/profile', authenticateToken, (req, res) => {
  const fullUser = users.find(u => u.id === req.user.id);
  if (!fullUser) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({
    user: {
      id: fullUser.id,
      username: fullUser.username,
      role: fullUser.role,
      firstName: fullUser.firstName,
      lastName: fullUser.lastName
    }
  });
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  const { firstName, lastName, password } = req.body;
  const user = users.find(u => u.id === req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  if (firstName !== undefined) user.firstName = firstName;
  if (lastName !== undefined) user.lastName = lastName;
  if (password) {
    user.password = await bcrypt.hash(password, 10);
  }
  res.json({
    message: 'Profile updated',
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName
    }
  });
});

app.get('/api/admin/dashboard', authenticateToken, authorizeRole('admin'), (req, res) => {
  res.json({ message: 'Welcome to admin dashboard!', data: 'Secret admin info' });
});

app.get('/api/content/guest', (req, res) => {
  res.json({ message: 'Public content for all visitors' });
});

app.get('/api/employees', authenticateToken, authorizeRole('admin'), (req, res) => {
  res.json({ employees });
});

app.get('/api/employees/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const employeeId = parseInt(req.params.id, 10);
  const employee = employees.find(e => e.id === employeeId);
  if (!employee) {
    return res.status(404).json({ error: 'Employee not found' });
  }
  res.json({ employee });
});

app.post('/api/employees', authenticateToken, authorizeRole('admin'), (req, res) => {
  const { employeeCode, name, email, position, department, hireDate } = req.body;

  if (!employeeCode || !email || !position || !department) {
    return res.status(400).json({
      error: 'Employee code, email, position, and department are required'
    });
  }

  const newEmployee = {
    id: employees.length + 1,
    employeeCode,
    name: name || email,
    email,
    position,
    department,
    hireDate: hireDate || null
  };

  employees.push(newEmployee);
  res.status(201).json({ message: 'Employee added', employee: newEmployee });
});

app.put('/api/employees/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const employeeId = parseInt(req.params.id, 10);
  const { employeeCode, name, email, position, department, hireDate } = req.body;

  const employee = employees.find(e => e.id === employeeId);
  if (!employee) {
    return res.status(404).json({ error: 'Employee not found' });
  }

  employee.employeeCode = employeeCode ?? employee.employeeCode;
  employee.name = name ?? employee.name;
  employee.email = email ?? employee.email;
  employee.position = position ?? employee.position;
  employee.department = department ?? employee.department;
  employee.hireDate = hireDate ?? employee.hireDate;

  res.json({ message: 'Employee updated', employee });
});

app.delete('/api/employees/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const employeeId = parseInt(req.params.id, 10);
  const index = employees.findIndex(e => e.id === employeeId);

  if (index === -1) {
    return res.status(404).json({ error: 'Employee not found' });
  }

  const removed = employees.splice(index, 1)[0];
  res.json({ message: 'Employee removed', employee: removed });
});

app.get('/api/accounts', authenticateToken, authorizeRole('admin'), (req, res) => {
  const safeUsers = users.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    firstName: u.firstName || '',
    lastName: u.lastName || '',
    verified: u.verified || false
  }));
  res.json({ accounts: safeUsers });
});

app.get('/api/accounts/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const user = users.find(u => u.id === userId);
  if (!user) {
    return res.status(404).json({ error: 'Account not found' });
  }
  res.json({
    account: {
      id: user.id,
      username: user.username,
      role: user.role,
      firstName: user.firstName || '',
      lastName: user.lastName || '',
      verified: user.verified || false
    }
  });
});

app.post('/api/accounts', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { username, password, role = 'user', firstName, lastName } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const existing = users.find(u => u.username === username);
  if (existing) {
    return res.status(409).json({ error: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: users.length + 1,
    username,
    password: hashedPassword,
    role,
    firstName: firstName || '',
    lastName: lastName || '',
    verified: false
  };

  users.push(newUser);
  res.status(201).json({
    message: 'Account created',
    account: {
      id: newUser.id,
      username: newUser.username,
      role: newUser.role,
      firstName: newUser.firstName,
      lastName: newUser.lastName,
      verified: newUser.verified
    }
  });
});

app.put('/api/accounts/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const { username, password, role, firstName, lastName, verified } = req.body;

  const user = users.find(u => u.id === userId);
  if (!user) {
    return res.status(404).json({ error: 'Account not found' });
  }

  user.username = username ?? user.username;
  user.role = role ?? user.role;
  user.firstName = firstName ?? user.firstName;
  user.lastName = lastName ?? user.lastName;
  user.verified = verified !== undefined ? verified : user.verified;

  if (password) {
    user.password = await bcrypt.hash(password, 10);
  }

  res.json({
    message: 'Account updated',
    account: {
      id: user.id,
      username: user.username,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName,
      verified: user.verified
    }
  });
});

app.delete('/api/accounts/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const index = users.findIndex(u => u.id === userId);

  if (index === -1) {
    return res.status(404).json({ error: 'Account not found' });
  }

  const removed = users.splice(index, 1)[0];
  res.json({ message: 'Account deleted', account: { id: removed.id, username: removed.username } });
});

app.get('/api/departments', authenticateToken, (req, res) => {
  res.json({ departments });
});

app.get('/api/departments/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const deptId = parseInt(req.params.id, 10);
  const dept = departments.find(d => d.id === deptId);
  if (!dept) {
    return res.status(404).json({ error: 'Department not found' });
  }
  res.json({ department: dept });
});

app.post('/api/departments', authenticateToken, authorizeRole('admin'), (req, res) => {
  const { name, description } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Department name is required' });
  }
  const existing = departments.find(d => d.name.toLowerCase() === name.toLowerCase());
  if (existing) {
    return res.status(409).json({ error: 'Department already exists' });
  }
  const newDept = { id: departments.length + 1, name, description: description || '' };
  departments.push(newDept);
  res.status(201).json({ message: 'Department added', department: newDept });
});

app.put('/api/departments/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const deptId = parseInt(req.params.id, 10);
  const { name, description } = req.body;
  const dept = departments.find(d => d.id === deptId);
  if (!dept) {
    return res.status(404).json({ error: 'Department not found' });
  }
  dept.name = name ?? dept.name;
  dept.description = description ?? dept.description;
  res.json({ message: 'Department updated', department: dept });
});

app.delete('/api/departments/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const deptId = parseInt(req.params.id, 10);
  const index = departments.findIndex(d => d.id === deptId);
  if (index === -1) {
    return res.status(404).json({ error: 'Department not found' });
  }
  const removed = departments.splice(index, 1)[0];
  res.json({ message: 'Department deleted', department: removed });
});

app.get('/api/requests', authenticateToken, (req, res) => {
  if (req.user.role === 'admin') {
    res.json({ requests });
  } else {
    res.json({ requests: requests.filter(r => r.userId === req.user.id) });
  }
});

app.post('/api/requests', authenticateToken, (req, res) => {
  const { type, items } = req.body;
  if (!type) {
    return res.status(400).json({ error: 'Request type is required' });
  }
  const newRequest = {
    id: requests.length + 1,
    userId: req.user.id,
    username: req.user.username,
    type,
    items: items || [],
    status: 'pending',
    createdAt: new Date().toISOString().split('T')[0]
  };
  requests.push(newRequest);
  res.status(201).json({ message: 'Request submitted', request: newRequest });
});

app.put('/api/requests/:id/status', authenticateToken, authorizeRole('admin'), (req, res) => {
  const reqId = parseInt(req.params.id, 10);
  const { status } = req.body;
  const request = requests.find(r => r.id === reqId);
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }
  request.status = status;
  res.json({ message: 'Request status updated', request });
});

app.delete('/api/requests/:id', authenticateToken, (req, res) => {
  const reqId = parseInt(req.params.id, 10);
  const index = requests.findIndex(r => r.id === reqId);
  if (index === -1) {
    return res.status(404).json({ error: 'Request not found' });
  }
  const request = requests[index];
  if (req.user.role !== 'admin' && request.userId !== req.user.id) {
    return res.status(403).json({ error: 'Access denied' });
  }
  const removed = requests.splice(index, 1)[0];
  res.json({ message: 'Request deleted', request: removed });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Access denied: insufficient permissions' });
    }
    next();
  };
}

app.listen(PORT, () => {
  console.log(` Backend running on http://localhost:${PORT}`);
  console.log(` Try logging in with:`);
  console.log(`  -Admin: username=admin, password=admin123`);
  console.log(`  -User:  username=alice, password=user123`);
});
