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
    valid_until: m.valid_until || null,
  };
}

function signToken(gymId) {
  return jwt.sign(
    { gymId, userId: gymId },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
}

// ---------- HEALTH ----------

router.get('/ping', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

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
      gym: { id: result.insertId, gym_name: gymName, email },
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
      gym: { id: gym.id, gym_name: gym.name, email: gym.email },
      token: signToken(gym.id),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.put('/auth/profile', auth, async (req, res) => {
  try {
    const gymName = ((req.body || {}).gym_name || '').trim();
    if (!gymName)
      return res.status(400).json({ error: 'Gym name is required' });

    await pool.query('UPDATE gyms SET name = ? WHERE id = ?', [gymName, req.gymId]);
    res.json({ gym: { id: req.gymId, gym_name: gymName } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.put('/auth/password', auth, async (req, res) => {
  try {
    const body = req.body || {};
    const currentPassword = body.current_password || '';
    const newPassword = body.new_password || '';

    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: 'All fields required' });
    if (newPassword.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const [rows] = await pool.query('SELECT password FROM gyms WHERE id = ?', [req.gymId]);
    if (rows.length === 0)
      return res.status(404).json({ error: 'Gym not found' });

    const valid = await bcrypt.compare(currentPassword, rows[0].password);
    if (!valid)
      return res.status(400).json({ error: 'Current password is incorrect' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE gyms SET password = ? WHERE id = ?', [hashed, req.gymId]);
    res.json({ message: 'Password updated' });
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
    const filter = (req.query.filter || '').trim();
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const pageSize = Math.min(100, parseInt(req.query.page_size || req.query.pageSize) || 25);
    const offset = (page - 1) * pageSize;
    const gymId = req.gymId;

    const today = isValidDate(req.query.today)
      ? req.query.today
      : new Date().toISOString().slice(0, 10);
    const soon = today;
    const weekEnd = new Date(today + 'T00:00:00Z');
    weekEnd.setUTCDate(weekEnd.getUTCDate() + 7);
    const weekEndStr = weekEnd.toISOString().slice(0, 10);

    let inner = 'WHERE m.gym_id = ?';
    const params = [gymId];
    if (search) {
      inner += ' AND (m.name LIKE ? OR m.phone LIKE ? OR m.member_code LIKE ?)';
      const term = `%${search}%`;
      params.push(term, term, term);
    }

    let outer = '';
    if (filter === 'active') {
      outer = 'WHERE valid_until >= ?';
      params.push(soon);
    } else if (filter === 'expiring') {
      outer = 'WHERE valid_until >= ? AND valid_until <= ?';
      params.push(soon, weekEndStr);
    } else if (filter === 'expired') {
      outer = 'WHERE valid_until < ?';
      params.push(soon);
    } else if (filter === 'none') {
      outer = 'WHERE valid_until IS NULL';
    }

    const base = `
      SELECT t.* FROM (
        SELECT m.*,
          (SELECT DATE_FORMAT(MAX(p.valid_until), '%Y-%m-%d') FROM payments p
           WHERE p.member_id = m.id AND p.gym_id = m.gym_id) AS valid_until
        FROM members m ${inner}
      ) t ${outer}`;

    const [members] = await pool.query(
      `${base} ORDER BY t.id DESC LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );
    const [countResult] = await pool.query(
      `SELECT COUNT(*) AS total FROM (${base}) c`,
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

router.get('/members/dues', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const gymId = req.gymId;

    const [rows] = await pool.query(
      `SELECT m.id, m.member_code, m.name, m.phone,
         DATE_FORMAT(MAX(p.valid_until), '%Y-%m-%d') AS valid_until
       FROM members m
       LEFT JOIN payments p ON p.member_id = m.id AND p.gym_id = m.gym_id
       WHERE m.gym_id = ?
       GROUP BY m.id, m.member_code, m.name, m.phone
       HAVING valid_until IS NULL OR valid_until < ?
       ORDER BY valid_until ASC, m.name ASC
       LIMIT 100`,
      [gymId, today]
    );

    res.json({ dues: rows.map(r => ({
      id: r.id,
      member_code: r.member_code,
      name: r.name,
      phone: r.phone,
      valid_until: r.valid_until || null,
    }))});
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

// ---------- PLANS ----------

const planFile = upload.single('qr');

function serializePlan(p) {
  return {
    id: p.id,
    name: p.name,
    amount: Number(p.amount),
    duration_months: p.duration_months,
    payment_link: p.payment_link,
    qr_url: p.qr_url,
  };
}

function readPlanBody(body) {
  body = body || {};
  return {
    name: (body.name || '').trim(),
    amount: Number(body.amount),
    duration: parseInt(body.duration_months, 10),
    link: (body.payment_link || '').trim(),
    removeQr: body.remove_qr === 'true',
  };
}

function planError(p) {
  if (!p.name) return 'Plan name is required';
  if (!Number.isFinite(p.amount) || p.amount <= 0 || p.amount >= 100000000)
    return 'Enter a valid amount';
  if (!Number.isInteger(p.duration) || p.duration < 1 || p.duration > 60)
    return 'Duration must be 1 to 60 months';
  if (p.link && (p.link.length > 500 || !/^https?:\/\//i.test(p.link)))
    return 'Payment link must start with http:// or https://';
  return null;
}

router.get('/plans', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM plans WHERE gym_id = ? ORDER BY amount ASC, id ASC',
      [req.gymId]
    );
    res.json({ plans: rows.map(serializePlan) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/plans', auth, planFile, async (req, res) => {
  try {
    const p = readPlanBody(req.body);
    const err = planError(p);
    if (err) return res.status(400).json({ error: err });

    let qrUrl = null;
    if (req.file) qrUrl = await uploadToCloudinary(req.file.buffer, 'qr');

    const [result] = await pool.query(
      'INSERT INTO plans (gym_id, name, amount, duration_months, payment_link, qr_url) VALUES (?, ?, ?, ?, ?, ?)',
      [req.gymId, p.name, p.amount, p.duration, p.link || null, qrUrl]
    );
    const [rows] = await pool.query('SELECT * FROM plans WHERE id = ?', [result.insertId]);
    res.status(201).json({ plan: serializePlan(rows[0]) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.put('/plans/:id', auth, planFile, async (req, res) => {
  try {
    const p = readPlanBody(req.body);
    const err = planError(p);
    if (err) return res.status(400).json({ error: err });

    const [existing] = await pool.query(
      'SELECT id FROM plans WHERE id = ? AND gym_id = ?',
      [req.params.id, req.gymId]
    );
    if (existing.length === 0)
      return res.status(404).json({ error: 'Plan not found' });

    let query = 'UPDATE plans SET name=?, amount=?, duration_months=?, payment_link=?';
    const params = [p.name, p.amount, p.duration, p.link || null];
    if (req.file) {
      query += ', qr_url=?';
      params.push(await uploadToCloudinary(req.file.buffer, 'qr'));
    } else if (p.removeQr) {
      query += ', qr_url=NULL';
    }
    query += ' WHERE id=? AND gym_id=?';
    params.push(req.params.id, req.gymId);
    await pool.query(query, params);

    const [rows] = await pool.query('SELECT * FROM plans WHERE id = ?', [req.params.id]);
    res.json({ plan: serializePlan(rows[0]) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.delete('/plans/:id', auth, async (req, res) => {
  try {
    const [result] = await pool.query(
      'DELETE FROM plans WHERE id = ? AND gym_id = ?',
      [req.params.id, req.gymId]
    );
    if (result.affectedRows === 0)
      return res.status(404).json({ error: 'Plan not found' });
    res.json({ message: 'Plan deleted' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- PAYMENTS ----------

function isValidDate(s) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  return !isNaN(d) && d.toISOString().slice(0, 10) === s;
}

function addMonths(dateStr, months) {
  const [y, m, d] = dateStr.split('-').map(Number);
  const target = new Date(Date.UTC(y, m - 1 + months, 1));
  const lastDay = new Date(
    Date.UTC(target.getUTCFullYear(), target.getUTCMonth() + 1, 0)
  ).getUTCDate();
  target.setUTCDate(Math.min(d, lastDay));
  return target.toISOString().slice(0, 10);
}

const PAYMENT_COLUMNS = `id, plan_id, plan_name, amount,
  DATE_FORMAT(paid_on, '%Y-%m-%d') AS paid_on,
  DATE_FORMAT(valid_until, '%Y-%m-%d') AS valid_until, note, method, receipt_no`;

function serializePayment(p) {
  return {
    id: p.id,
    plan_id: p.plan_id,
    plan_name: p.plan_name,
    amount: Number(p.amount),
    paid_on: p.paid_on,
    valid_until: p.valid_until,
    note: p.note,
    method: p.method || 'cash',
    receipt_no: p.receipt_no || null,
  };
}

const PAYMENT_METHODS = ['cash', 'upi', 'card'];

(async () => {
  try {
    const [m] = await pool.query("SHOW COLUMNS FROM payments LIKE 'method'");
    if (m.length === 0) {
      await pool.query(
        "ALTER TABLE payments ADD COLUMN method VARCHAR(10) NOT NULL DEFAULT 'cash'"
      );
    }
    const [r] = await pool.query("SHOW COLUMNS FROM payments LIKE 'receipt_no'");
    if (r.length === 0) {
      await pool.query('ALTER TABLE payments ADD COLUMN receipt_no VARCHAR(20) NULL');
      await pool.query(
        'ALTER TABLE payments ADD UNIQUE INDEX uq_receipt (gym_id, receipt_no)'
      );
    }
  } catch (e) {
    console.error('Payment columns check failed:', e.message);
  }
})();

async function nextReceiptNo(gymId, year) {
  const prefix = `RCP-${year}-`;
  const [rows] = await pool.query(
    `SELECT MAX(CAST(SUBSTRING(receipt_no, ?) AS UNSIGNED)) AS n
     FROM payments WHERE gym_id = ? AND receipt_no LIKE ?`,
    [prefix.length + 1, gymId, prefix + '%']
  );
  return prefix + String((rows[0].n || 0) + 1).padStart(4, '0');
}

async function memberBelongsToGym(memberId, gymId) {
  const [rows] = await pool.query(
    'SELECT id FROM members WHERE id = ? AND gym_id = ?',
    [memberId, gymId]
  );
  return rows.length > 0;
}

router.get('/members/:id/payments', auth, async (req, res) => {
  try {
    if (!(await memberBelongsToGym(req.params.id, req.gymId)))
      return res.status(404).json({ error: 'Member not found' });

    const [rows] = await pool.query(
      `SELECT ${PAYMENT_COLUMNS} FROM payments
       WHERE member_id = ? AND gym_id = ?
       ORDER BY paid_on DESC, id DESC`,
      [req.params.id, req.gymId]
    );
    const payments = rows.map(serializePayment);
    const validUntil = payments.reduce(
      (max, p) => (!max || p.valid_until > max ? p.valid_until : max),
      null
    );
    res.json({ payments, valid_until: validUntil });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/members/:id/payments', auth, async (req, res) => {
  try {
    const body = req.body || {};
    const planId = parseInt(body.plan_id, 10);
    const note = (body.note || '').trim().slice(0, 255);
    const paidOn = (body.paid_on || new Date().toISOString().slice(0, 10)).trim();
    const method = (body.method || 'cash').toString().toLowerCase();

    if (!PAYMENT_METHODS.includes(method))
      return res.status(400).json({ error: 'Invalid payment method' });
    if (!planId) return res.status(400).json({ error: 'Select a plan' });
    if (!isValidDate(paidOn))
      return res.status(400).json({ error: 'Invalid payment date' });
    if (!(await memberBelongsToGym(req.params.id, req.gymId)))
      return res.status(404).json({ error: 'Member not found' });

    const [plans] = await pool.query(
      'SELECT * FROM plans WHERE id = ? AND gym_id = ?',
      [planId, req.gymId]
    );
    if (plans.length === 0)
      return res.status(404).json({ error: 'Plan not found' });
    const plan = plans[0];

    const [latest] = await pool.query(
      `SELECT DATE_FORMAT(MAX(valid_until), '%Y-%m-%d') AS v
       FROM payments WHERE member_id = ? AND gym_id = ?`,
      [req.params.id, req.gymId]
    );
    const current = latest[0].v;
    const start = current && current > paidOn ? current : paidOn;
    const validUntil = addMonths(start, plan.duration_months);

    let result;
    for (let attempt = 0; attempt < 3; attempt++) {
      const receiptNo = await nextReceiptNo(req.gymId, paidOn.slice(0, 4));
      try {
        [result] = await pool.query(
          `INSERT INTO payments
           (gym_id, member_id, plan_id, plan_name, amount, paid_on, valid_until, note, method, receipt_no)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [req.gymId, req.params.id, plan.id, plan.name, plan.amount, paidOn, validUntil, note || null, method, receiptNo]
        );
        break;
      } catch (err) {
        if (err.code !== 'ER_DUP_ENTRY' || attempt === 2) throw err;
      }
    }
    const [rows] = await pool.query(
      `SELECT ${PAYMENT_COLUMNS} FROM payments WHERE id = ?`,
      [result.insertId]
    );
    res.status(201).json({ payment: serializePayment(rows[0]), valid_until: validUntil });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.delete('/payments/:id', auth, async (req, res) => {
  try {
    const [result] = await pool.query(
      'DELETE FROM payments WHERE id = ? AND gym_id = ?',
      [req.params.id, req.gymId]
    );
    if (result.affectedRows === 0)
      return res.status(404).json({ error: 'Payment not found' });
    res.json({ message: 'Payment deleted' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- ATTENDANCE ----------

(async () => {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS attendance (
      id INT AUTO_INCREMENT PRIMARY KEY,
      gym_id INT NOT NULL,
      member_id INT NOT NULL,
      day DATE NOT NULL,
      checked_in_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_att (gym_id, member_id, day),
      KEY idx_att_day (gym_id, day)
    )`);
  } catch (e) {
    console.error('attendance table', e.message);
  }
})();

(async () => {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS membership_freezes (
      id INT AUTO_INCREMENT PRIMARY KEY,
      gym_id INT NOT NULL,
      member_id INT NOT NULL,
      frozen_on DATE NOT NULL,
      freeze_days INT NOT NULL,
      new_valid_until DATE NOT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      KEY idx_freeze_member (gym_id, member_id)
    )`);
  } catch (e) {
    console.error('membership_freezes table', e.message);
  }
})();

router.post('/attendance/checkin', auth, async (req, res) => {
  try {
    const body = req.body || {};
    const memberId = parseInt(body.member_id, 10);
    const today = isValidDate(body.today || '')
      ? body.today
      : new Date().toISOString().slice(0, 10);

    if (!memberId)
      return res.status(400).json({ error: 'member_id is required' });

    const [members] = await pool.query(
      'SELECT id, name FROM members WHERE id = ? AND gym_id = ?',
      [memberId, req.gymId]
    );
    if (members.length === 0)
      return res.status(404).json({ error: 'Member not found' });

    const member = members[0];

    const [[latest]] = await pool.query(
      `SELECT DATE_FORMAT(MAX(valid_until), '%Y-%m-%d') AS valid_until
       FROM payments WHERE member_id = ? AND gym_id = ?`,
      [memberId, req.gymId]
    );
    const validUntil = latest.valid_until || null;

    let memberStatus;
    if (!validUntil) {
      memberStatus = 'no_plan';
    } else if (validUntil >= today) {
      memberStatus = 'active';
    } else {
      memberStatus = 'expired';
    }

    let alreadyCheckedIn = false;
    if (memberStatus === 'active') {
      try {
        await pool.query(
          'INSERT INTO attendance (gym_id, member_id, day) VALUES (?, ?, ?)',
          [req.gymId, memberId, today]
        );
      } catch (e) {
        if (e.code === 'ER_DUP_ENTRY') {
          alreadyCheckedIn = true;
        } else {
          throw e;
        }
      }
    }

    res.json({
      status: memberStatus,
      member_name: member.name,
      valid_until: validUntil,
      already_checked_in: alreadyCheckedIn,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/attendance/member/:id', auth, async (req, res) => {
  try {
    if (!(await memberBelongsToGym(req.params.id, req.gymId)))
      return res.status(404).json({ error: 'Member not found' });

    const [rows] = await pool.query(
      `SELECT DATE_FORMAT(day, '%Y-%m-%d') AS day
       FROM attendance
       WHERE member_id = ? AND gym_id = ?
       ORDER BY day DESC
       LIMIT 90`,
      [req.params.id, req.gymId]
    );

    res.json({ days: rows.map(r => r.day) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/members/:id/freeze', auth, async (req, res) => {
  try {
    const body = req.body || {};
    const freezeDays = parseInt(body.freeze_days, 10);

    if (!freezeDays || freezeDays < 1 || freezeDays > 365)
      return res.status(400).json({ error: 'freeze_days must be between 1 and 365' });

    if (!(await memberBelongsToGym(req.params.id, req.gymId)))
      return res.status(404).json({ error: 'Member not found' });

    const today = new Date().toISOString().slice(0, 10);

    const [[latest]] = await pool.query(
      `SELECT id, DATE_FORMAT(MAX(valid_until), '%Y-%m-%d') AS valid_until
       FROM payments WHERE member_id = ? AND gym_id = ?`,
      [req.params.id, req.gymId]
    );

    if (!latest.valid_until || latest.valid_until < today)
      return res.status(400).json({ error: 'No active membership to freeze' });

    // extend valid_until by freeze_days on all payments for this member (extend the max)
    const currentEnd = latest.valid_until;
    const newEnd = new Date(currentEnd + 'T00:00:00Z');
    newEnd.setUTCDate(newEnd.getUTCDate() + freezeDays);
    const newEndStr = newEnd.toISOString().slice(0, 10);

    // update the latest payment's valid_until
    await pool.query(
      `UPDATE payments SET valid_until = ?
       WHERE member_id = ? AND gym_id = ?
         AND DATE_FORMAT(valid_until, '%Y-%m-%d') = ?`,
      [newEndStr, req.params.id, req.gymId, currentEnd]
    );

    await pool.query(
      `INSERT INTO membership_freezes (gym_id, member_id, frozen_on, freeze_days, new_valid_until)
       VALUES (?, ?, ?, ?, ?)`,
      [req.gymId, req.params.id, today, freezeDays, newEndStr]
    );

    res.json({ valid_until: newEndStr, freeze_days: freezeDays });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- DASHBOARD ----------

router.get('/dashboard', auth, async (req, res) => {
  try {
    const re = /^\d{4}-\d{2}-\d{2}$/;
    const today = re.test(req.query.today || '') ? req.query.today : null;
    if (!today) return res.status(400).json({ error: 'today is required' });

    const gid = req.gymId;
    const [[tot]] = await pool.query(
      'SELECT COUNT(*) AS c FROM members WHERE gym_id = ?',
      [gid]
    );
    const [[act]] = await pool.query(
      `SELECT COUNT(*) AS c FROM (
         SELECT member_id FROM payments WHERE gym_id = ?
         GROUP BY member_id HAVING MAX(valid_until) >= ?
       ) t`,
      [gid, today]
    );
    const [[exp]] = await pool.query(
      `SELECT COUNT(*) AS c FROM (
         SELECT member_id FROM payments WHERE gym_id = ?
         GROUP BY member_id
         HAVING MAX(valid_until) >= ? AND MAX(valid_until) <= DATE_ADD(?, INTERVAL 7 DAY)
       ) t`,
      [gid, today, today]
    );
    const monthStart = today.slice(0, 8) + '01';
    const [[rev]] = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS s FROM payments
       WHERE gym_id = ? AND paid_on >= ?
         AND paid_on < DATE_ADD(?, INTERVAL 1 MONTH)`,
      [gid, monthStart, monthStart]
    );
    const [[chk]] = await pool.query(
      'SELECT COUNT(*) AS c FROM attendance WHERE gym_id = ? AND day = ?',
      [gid, today]
    );

    res.json({
      total_members: tot.c,
      active_members: act.c,
      expiring_week: exp.c,
      month_revenue: Number(rev.s),
      today_checkins: chk.c,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/dashboard/revenue-chart', auth, async (req, res) => {
  try {
    const gid = req.gymId;
    const [rows] = await pool.query(
      `SELECT
         DATE_FORMAT(paid_on, '%Y-%m') AS month_key,
         DATE_FORMAT(MIN(paid_on), '%b %Y') AS label,
         COALESCE(SUM(amount), 0) AS amount
       FROM payments
       WHERE gym_id = ?
         AND paid_on >= DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL 5 MONTH), '%Y-%m-01')
       GROUP BY month_key
       ORDER BY month_key ASC`,
      [gid]
    );

    res.json({ months: rows.map(r => ({ label: r.label, amount: Number(r.amount) })) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/dashboard/expiring', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const weekEnd = new Date(today + 'T00:00:00Z');
    weekEnd.setUTCDate(weekEnd.getUTCDate() + 7);
    const weekEndStr = weekEnd.toISOString().slice(0, 10);

    const [rows] = await pool.query(
      `SELECT m.id, m.member_code, m.name, m.phone,
         DATE_FORMAT(MAX(p.valid_until), '%Y-%m-%d') AS valid_until
       FROM members m
       JOIN payments p ON p.member_id = m.id AND p.gym_id = m.gym_id
       WHERE m.gym_id = ?
       GROUP BY m.id, m.member_code, m.name, m.phone
       HAVING valid_until >= ? AND valid_until <= ?
       ORDER BY valid_until ASC`,
      [req.gymId, today, weekEndStr]
    );

    res.json({ members: rows.map(r => ({
      id: r.id,
      member_code: r.member_code,
      name: r.name,
      phone: r.phone,
      valid_until: r.valid_until,
    }))});
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;