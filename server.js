const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { Anthropic } = require('@anthropic-ai/sdk');

const app = express();
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000' }));
app.use(express.json({ limit: '10mb' }));

const DATA_FILE = path.join(__dirname, 'data', 'db.json');
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';

// ── DATA HELPERS ──────────────────────────────────────────────
const loadDB = () => {
  if (!fs.existsSync(DATA_FILE)) {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [], businesses: {} }));
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
};
const saveDB = (db) => fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ── AUTH ROUTES ───────────────────────────────────────────────
// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, businessName, pin } = req.body;
    if (!name || !email || !password || !businessName)
      return res.status(400).json({ error: 'All fields required' });

    const db = loadDB();
    if (db.users.find(u => u.email === email.toLowerCase()))
      return res.status(400).json({ error: 'Email already registered' });

    const hashedPw = await bcrypt.hash(password, 10);
    const hashedPin = pin ? await bcrypt.hash(pin, 10) : null;
    const userId = Date.now().toString(36);

    const user = {
      id: userId, name, email: email.toLowerCase(),
      password: hashedPw, pin: hashedPin,
      role: 'owner', createdAt: new Date().toISOString(),
      businessId: userId
    };

    db.users.push(user);
    db.businesses[userId] = {
      businessName, bankName: 'Bank Account',
      vatEnabled: false, bank: 0, cashOnHand: 0,
      netIncome: 0, netIncomeMonth: '',
      revenues: [], expenses: [], sales: [],
      payables: [], receivables: [],
      vendors: [], partners: [],
      savedSaleItems: [], savedExpenseItems: [],
      users: [userId]
    };

    saveDB(db);
    const token = jwt.sign({ userId, businessId: userId }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: userId, name, email: user.email, role: 'owner' } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.email === email?.toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id, businessId: user.businessId }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Change Password
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) return res.status(401).json({ error: 'Current password incorrect' });

    user.password = await bcrypt.hash(newPassword, 10);
    saveDB(db);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Change PIN
app.post('/api/auth/change-pin', auth, async (req, res) => {
  try {
    const { pin } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.pin = await bcrypt.hash(pin, 10);
    saveDB(db);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add team member (owner only)
app.post('/api/auth/add-member', auth, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const db = loadDB();
    const biz = db.businesses[req.user.businessId];
    const requester = db.users.find(u => u.id === req.user.userId);
    if (requester.role !== 'owner') return res.status(403).json({ error: 'Only owner can add members' });
    if (db.users.find(u => u.email === email?.toLowerCase()))
      return res.status(400).json({ error: 'Email already registered' });

    const userId = Date.now().toString(36) + 'b';
    const member = {
      id: userId, name, email: email.toLowerCase(),
      password: await bcrypt.hash(password, 10),
      role: role || 'staff', businessId: req.user.businessId,
      createdAt: new Date().toISOString()
    };
    db.users.push(member);
    biz.users.push(userId);
    saveDB(db);
    res.json({ success: true, member: { id: userId, name, email: member.email, role: member.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── BUSINESS DATA ─────────────────────────────────────────────
app.get('/api/business', auth, (req, res) => {
  const db = loadDB();
  const biz = db.businesses[req.user.businessId];
  if (!biz) return res.status(404).json({ error: 'Business not found' });
  res.json(biz);
});

app.put('/api/business', auth, (req, res) => {
  const db = loadDB();
  db.businesses[req.user.businessId] = { ...db.businesses[req.user.businessId], ...req.body };
  saveDB(db);
  res.json({ success: true });
});

// ── AI PROXY (keeps API key on server) ───────────────────────
app.post('/api/ai/chat', auth, async (req, res) => {
  try {
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const { messages, system } = req.body;
    const response = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      system,
      messages
    });
    res.json({ content: response.content });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// AI PDF extraction proxy
app.post('/api/ai/extract-pdf', auth, async (req, res) => {
  try {
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const { pdfBase64 } = req.body;
    const response = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1500,
      messages: [{
        role: 'user',
        content: [
          { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: pdfBase64 } },
          { type: 'text', text: 'Extract all financial transactions. Return ONLY a JSON array. Each item: {date:"DD/MM/YYYY",description:"string",amount:number}. No markdown.' }
        ]
      }]
    });
    const text = response.content.map(c => c.text || '').join('');
    const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());
    res.json({ entries: parsed });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve React build in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../frontend/build')));
  app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../frontend/build/index.html')));
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
