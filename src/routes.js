const express = require('express');
const router = express.Router();
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const cloudinary = require('./cloudinary');
const { auth } = require('./middleware');
require('dotenv').config();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

async function uploadToCloudinary(buffer, folder) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: `gym-app/${folder}`, resource_type: 'image' },
      (error, result) => {
        if (error) reject(error);
        else resolve(result.secure_url);
      }
    );
    stream.end(buffer);
  });
}

function formatDate(d) {
  if (!d) return '';
  const dt = new Date(d);
  if (isNaN(dt)) return String(d);
  return dt.toISOString().slice(0, 10);
}

// Response shape the Flutter Member model expects (snake_case)
function serializeMember(m) {
  return {
    id: m.id,
    member_code: m.member_code,
    gym_id: m.gym_id,
    name: m.name,
    parentage: m.parentage,
    address: m.address,
    phone: m.phone,
    gender: m.gender,
    joined_on: formatDate(m.joined_on),
    photo_url: m.photo_url,
    aadhaar_url: m.aadhaar_url,
  };
}

function signToken(gymId) {
  return jwt.sign(
    { gymId, userId: gymId },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
}

// ---------- AUTH ----------

router.post('/auth/register', async (req, res) => {
  try {
    const body = req.body || {};
    const gymName = (body.gym_name || body.gymName || body.name || '').trim();
    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || '';

    if (!gymName || !email || !password)
      return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const [existing] = await pool.query('SELECT id FROM gyms WHERE email = ?', [email]);
    if (existing.length > 0)
      return res.status(400).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO gyms (name, email, password) VALUES (?, ?, ?)',
      [gymName, email, hashed]
    );

    res.status(200).json({
      gym: {
        id: result.insertId,
        gym_name: gymName,
        email
      },
      token: signToken(result.insertId),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/auth/login', async (req, res) => {
  try {
    const body = req.body || {};
    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || '';

    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const [rows] = await pool.query('SELECT * FROM gyms WHERE email = ?', [email]);
    if (rows.length === 0)
      return res.status(401).json({ error: 'Invalid email or password' });

    const gym = rows[0];
    const valid = await bcrypt.compare(password, gym.password);
    if (!valid)
      return res.status(401).json({ error: 'Invalid email or password' });

    res.json({
      gym: {
        id: gym.id,
        gym_name: gym.name,
        email: gym.email,
      },
      token: signToken(gym.id),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- MEMBERS ----------

const memberFiles = upload.fields([
  { name: 'photo', maxCount: 1 },
  { name: 'aadhaar', maxCount: 1 },
]);

function readMemberBody(body) {
  body = body || {};
  return {
    name: (body.name || '').trim(),
    parentage: (body.parentage || '').trim(),
    address: (body.address || '').trim(),
    phone: (body.phone || '').trim(),
    gender: (body.gender || '').trim(),
    joinedOn: (body.joined_on || body.joinedOn || '').trim(),
  };
}

router.post('/members', auth, memberFiles, async (req, res) => {
  try {
    const { name, parentage, address, phone, gender, joinedOn } = readMemberBody(req.body);
    const gymId = req.gymId;

    if (!name || !parentage || !address || !phone || !gender || !joinedOn)
      return res.status(400).json({ error: 'All fields required' });

    const [existing] = await pool.query(
      'SELECT id FROM members WHERE phone = ? AND gym_id = ?',
      [phone, gymId]
    );
    if (existing.length > 0)
      return res.status(400).json({ error: 'Phone number already registered' });

    const [last] = await pool.query(
      'SELECT member_code FROM members WHERE gym_id = ? ORDER BY id DESC LIMIT 1',
      [gymId]
    );
    let nextNum = 1;
    if (last.length > 0) {
      const lastNum = parseInt(String(last[0].member_code).replace(/[^0-9]/g, '')) || 0;
      nextNum = lastNum + 1;
    }
    const memberCode = 'GYM-' + String(nextNum).padStart(4, '0');

    let photoUrl = null;
    let aadhaarUrl = null;
    if (req.files?.photo) photoUrl = await uploadToCloudinary(req.files.photo[0].buffer, 'photos');
    if (req.files?.aadhaar) aadhaarUrl = await uploadToCloudinary(req.files.aadhaar[0].buffer, 'aadhaar');

    const [result] = await pool.query(
      'INSERT INTO members (gym_id, member_code, name, parentage, address, phone, gender, joined_on, photo_url, aadhaar_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [gymId, memberCode, name, parentage, address, phone, gender, joinedOn, photoUrl, aadhaarUrl]
    );

    const [rows] = await pool.query('SELECT * FROM members WHERE id = ?', [result.insertId]);
    res.status(201).json({ member: serializeMember(rows[0]) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/members', auth, async (req, res) => {
  try {
    const search = (req.query.search || '').trim();
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const pageSize = Math.min(100, parseInt(req.query.page_size || req.query.pageSize) || 25);
    const offset = (page - 1) * pageSize;
    const gymId = req.gymId;

    let where = 'WHERE gym_id = ?';
    const params = [gymId];
    if (search) {
      where += ' AND (name LIKE ? OR phone LIKE ? OR member_code LIKE ?)';
      const term = `%${search}%`;
      params.push(term, term, term);
    }

    const [members] = await pool.query(
      `SELECT * FROM members ${where} ORDER BY id DESC LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );
    const [countResult] = await pool.query(
      `SELECT COUNT(*) AS total FROM members ${where}`,
      params
    );
    const total = countResult[0].total;

    res.json({
      members: members.map(serializeMember),
      total,
      page,
      has_more: offset + members.length < total,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/members/:id', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM members WHERE id = ? AND gym_id = ?',
      [req.params.id, req.gymId]
    );
    if (rows.length === 0)
      return res.status(404).json({ error: 'Member not found' });

    res.json(serializeMember(rows[0]));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.put('/members/:id', auth, memberFiles, async (req, res) => {
  try {
    const { name, parentage, address, phone, gender, joinedOn } = readMemberBody(req.body);
    const gymId = req.gymId;

    if (!name || !parentage || !address || !phone || !gender || !joinedOn)
      return res.status(400).json({ error: 'All fields required' });

    const [existing] = await pool.query(
      'SELECT id FROM members WHERE id = ? AND gym_id = ?',
      [req.params.id, gymId]
    );
    if (existing.length === 0)
      return res.status(404).json({ error: 'Member not found' });

    const [phoneCheck] = await pool.query(
      'SELECT id FROM members WHERE phone = ? AND gym_id = ? AND id != ?',
      [phone, gymId, req.params.id]
    );
    if (phoneCheck.length > 0)
      return res.status(400).json({ error: 'Phone already used by another member' });

    let photoUrl = null;
    let aadhaarUrl = null;
    if (req.files?.photo) photoUrl = await uploadToCloudinary(req.files.photo[0].buffer, 'photos');
    if (req.files?.aadhaar) aadhaarUrl = await uploadToCloudinary(req.files.aadhaar[0].buffer, 'aadhaar');

    let query = 'UPDATE members SET name=?, parentage=?, address=?, phone=?, gender=?, joined_on=?';
    const params = [name, parentage, address, phone, gender, joinedOn];
    if (photoUrl) { query += ', photo_url=?'; params.push(photoUrl); }
    if (aadhaarUrl) { query += ', aadhaar_url=?'; params.push(aadhaarUrl); }
    query += ' WHERE id=? AND gym_id=?';
    params.push(req.params.id, gymId);

    await pool.query(query, params);

    const [rows] = await pool.query('SELECT * FROM members WHERE id = ?', [req.params.id]);
    res.json({ member: serializeMember(rows[0]) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.delete('/members/:id', auth, async (req, res) => {
  try {
    const [existing] = await pool.query(
      'SELECT id FROM members WHERE id = ? AND gym_id = ?',
      [req.params.id, req.gymId]
    );
    if (existing.length === 0)
      return res.status(404).json({ error: 'Member not found' });

    await pool.query('DELETE FROM members WHERE id = ? AND gym_id = ?', [req.params.id, req.gymId]);
    res.json({ message: 'Member deleted successfully' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;