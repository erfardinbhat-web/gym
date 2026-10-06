const express = require('express');
const router = express.Router();
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const cloudinary = require('./cloudinary');
const { auth } = require('./middleware');
require('dotenv').config();

const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// Upload image to Cloudinary
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

// Register gym
router.post('/auth/register', async (req, res) => {
  try {
    const { gymName, email, password } = req.body;
    if (!gymName || !email || !password)
      return res.status(400).json({ ok: false, error: 'All fields required' });

    const [existing] = await pool.query('SELECT id FROM gyms WHERE email = ?', [email]);
    if (existing.length > 0)
      return res.status(400).json({ ok: false, error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO gyms (name, email, password) VALUES (?, ?, ?)',
      [gymName, email, hashed]
    );

    const token = jwt.sign(
      { gymId: result.insertId, userId: result.insertId },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ ok: true, token, gymId: result.insertId, gymName });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Login gym
router.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ ok: false, error: 'Email and password required' });

    const [rows] = await pool.query('SELECT * FROM gyms WHERE email = ?', [email]);
    if (rows.length === 0)
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });

    const gym = rows[0];
    const valid = await bcrypt.compare(password, gym.password);
    if (!valid)
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });

    const token = jwt.sign(
      { gymId: gym.id, userId: gym.id },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ ok: true, token, gymId: gym.id, gymName: gym.name });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Create member
router.post('/members', auth, upload.fields([
  { name: 'photo', maxCount: 1 },
  { name: 'aadhaar', maxCount: 1 }
]), async (req, res) => {
  try {
    const { name, parentage, address, phone, gender, joinedOn } = req.body;
    const gymId = req.gymId;

    if (!name || !parentage || !address || !phone || !gender || !joinedOn)
      return res.status(400).json({ ok: false, error: 'All fields required' });

    const [existing] = await pool.query(
      'SELECT id FROM members WHERE phone = ? AND gym_id = ?',
      [phone, gymId]
    );
    if (existing.length > 0)
      return res.status(400).json({ ok: false, error: 'Phone number already registered' });

    const [last] = await pool.query(
      'SELECT member_code FROM members WHERE gym_id = ? ORDER BY created_at DESC LIMIT 1',
      [gymId]
    );
    let nextNum = 1;
    if (last.length > 0) {
      const lastNum = parseInt(last[0].member_code.replace(/[^0-9]/g, '')) || 0;
      nextNum = lastNum + 1;
    }
    const memberCode = 'GYM-' + String(nextNum).padStart(4, '0');

    let photoUrl = null;
    let aadhaarUrl = null;

    if (req.files?.photo) {
      photoUrl = await uploadToCloudinary(req.files.photo[0].buffer, 'photos');
    }
    if (req.files?.aadhaar) {
      aadhaarUrl = await uploadToCloudinary(req.files.aadhaar[0].buffer, 'aadhaar');
    }

    await pool.query(
      'INSERT INTO members (gym_id, member_code, name, parentage, address, phone, gender, joined_on, photo_url, aadhaar_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [gymId, memberCode, name, parentage, address, phone, gender, joinedOn, photoUrl, aadhaarUrl]
    );

    res.json({ ok: true, memberCode });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// List members
router.get('/members', auth, async (req, res) => {
  try {
    const { search = '', page = 1, pageSize = 25 } = req.query;
    const gymId = req.gymId;
    const offset = (page - 1) * pageSize;

    let query = 'SELECT * FROM members WHERE gym_id = ?';
    let countQuery = 'SELECT COUNT(*) as total FROM members WHERE gym_id = ?';
    const params = [gymId];

    if (search) {
      query += ' AND (name LIKE ? OR phone LIKE ? OR member_code LIKE ?)';
      countQuery += ' AND (name LIKE ? OR phone LIKE ? OR member_code LIKE ?)';
      const term = `%${search}%`;
      params.push(term, term, term);
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(pageSize), parseInt(offset));

    const [members] = await pool.query(query, params);
    const [countResult] = await pool.query(countQuery, params.slice(0, -2));
    const total = countResult[0].total;

    res.json({
      ok: true,
      members: members.map(m => ({
        memberId: m.id.toString(),
        memberCode: m.member_code,
        gymId: m.gym_id.toString(),
        name: m.name,
        phone: m.phone,
        gender: m.gender,
        joinedOn: m.joined_on ? new Date(m.joined_on).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '',
        parentage: m.parentage,
        address: m.address,
        photoUrl: m.photo_url,
        aadhaarUrl: m.aadhaar_url,
      })),
      total,
      page: parseInt(page),
      hasMore: offset + parseInt(pageSize) < total,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Get single member
router.get('/members/:id', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM members WHERE id = ? AND gym_id = ?',
      [req.params.id, req.gymId]
    );
    if (rows.length === 0)
      return res.status(404).json({ ok: false, error: 'Member not found' });

    const m = rows[0];
    res.json({
      ok: true,
      member: {
        memberId: m.id.toString(),
        memberCode: m.member_code,
        gymId: m.gym_id.toString(),
        name: m.name,
        phone: m.phone,
        gender: m.gender,
        joinedOn: m.joined_on ? new Date(m.joined_on).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '',
        parentage: m.parentage,
        address: m.address,
        photoUrl: m.photo_url,
        aadhaarUrl: m.aadhaar_url,
      }
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Update member
router.put('/members/:id', auth, upload.fields([
  { name: 'photo', maxCount: 1 },
  { name: 'aadhaar', maxCount: 1 }
]), async (req, res) => {
  try {
    const { name, parentage, address, phone, gender, joinedOn } = req.body;
    const gymId = req.gymId;

    const [existing] = await pool.query(
      'SELECT id FROM members WHERE id = ? AND gym_id = ?',
      [req.params.id, gymId]
    );
    if (existing.length === 0)
      return res.status(404).json({ ok: false, error: 'Member not found' });

    const [phoneCheck] = await pool.query(
      'SELECT id FROM members WHERE phone = ? AND gym_id = ? AND id != ?',
      [phone, gymId, req.params.id]
    );
    if (phoneCheck.length > 0)
      return res.status(400).json({ ok: false, error: 'Phone already used by another member' });

    let photoUrl = null;
    let aadhaarUrl = null;

    if (req.files?.photo) {
      photoUrl = await uploadToCloudinary(req.files.photo[0].buffer, 'photos');
    }
    if (req.files?.aadhaar) {
      aadhaarUrl = await uploadToCloudinary(req.files.aadhaar[0].buffer, 'aadhaar');
    }

    let query = 'UPDATE members SET name=?, parentage=?, address=?, phone=?, gender=?, joined_on=?';
    const params = [name, parentage, address, phone, gender, joinedOn];

    if (photoUrl) { query += ', photo_url=?'; params.push(photoUrl); }
    if (aadhaarUrl) { query += ', aadhaar_url=?'; params.push(aadhaarUrl); }

    query += ' WHERE id=? AND gym_id=?';
    params.push(req.params.id, gymId);

    await pool.query(query, params);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Delete member
router.delete('/members/:id', auth, async (req, res) => {
  try {
    const [existing] = await pool.query(
      'SELECT id FROM members WHERE id = ? AND gym_id = ?',
      [req.params.id, req.gymId]
    );
    if (existing.length === 0)
      return res.status(404).json({ ok: false, error: 'Member not found' });

    await pool.query('DELETE FROM members WHERE id = ? AND gym_id = ?', [req.params.id, req.gymId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

module.exports = router;
