// server.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const pool = require('./db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use('/uploads', express.static('uploads'));

// مفتاح JWT
//const JWT_SECRET = "my_secret_key";

const JWT_SECRET = process.env.JWT_SECRET;

//تحقق من ان سيرفر شغال
app.get('/health', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 AS ok');
    res.json({ status: 'OK', db: 'MySQL', ok: rows[0].ok });
  } catch (e) {
    res.status(500).json({ status: 'DB_ERROR', error: e.message });
    console.log(e.message)
  }
});

// ✅ 1. تسجيل حساب جديد (Register)
app.post('/auth/register', async (req, res) => {
  const { national_id, phone, password, confirm_password } = req.body;

  //  التحقق من الحقول
  if (!national_id || !phone || !password || !confirm_password) {
    return res.status(400).json({ message: "ادخل جميع الحقول مطلوبة" });
  }

  try {
    // التحقق من وجود المواطن في السجل المدني
    const [civil] = await pool.execute(
      "SELECT * FROM person_card WHERE national_id = ?",
      [national_id]
    );

    if (civil.length === 0) {
      return res.status(404).json({ message: "المواطن غير موجود في السجل المدني" });
    }

    // التحقق من أنّ رقم الهاتف ملك لنفس المواطن
    const [telecom] = await pool.execute(
      "SELECT * FROM telecom_company WHERE phone_number = ? AND national_id = ?",
      [phone, national_id]
    );

    if (telecom.length === 0) {
      return res.status(400).json({ message: "هذا الرقم ليس مسجلاً باسمك" });
    }

    // التحقق إن كان لديه حساب مسبقًا
    const [users] = await pool.execute(
      "SELECT * FROM users WHERE national_id = ?",
      [national_id]
    );

    if (users.length > 0) {
      return res.status(400).json({ message: "المستخدم مسجل مسبقًا" });
    }

    // التحقق من تطابق كلمة المرور
    if (password !== confirm_password) {
      return res.status(400).json({ message: "كلمة المرور غير متطابقة" });
    }

    // تشفير كلمة المرور
    const hashedPassword = await bcrypt.hash(password, 10);

    // إنشاء المستخدم
    await pool.execute(
      "INSERT INTO users (national_id, password_hash) VALUES (?, ?)",
      [national_id, hashedPassword]
    );

    // نتيجة النجاح
    return res.json({ message: "تم إنشاء الحساب بنجاح، قم الان بتسجيل الدخول" });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "خطأ في الخادم" });
  }
});


// ✅ 2. تسجيل الدخول (Login)
app.post('/auth/login', async (req, res) => {
  const { national_id, password } = req.body;

  if (!national_id || !password) {
    return res.status(400).json({ message: "مطلوب الرقم الوطني وكلمة المرور" });
  }

  try {
    const [users] = await pool.execute("SELECT * FROM users WHERE national_id = ?", [national_id]);
    if (users.length === 0) {
      return res.status(404).json({ message: "المستخدم غير موجود" });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ message: "كلمة المرور غير صحيحة" });
    }

    // توليد رمز تحقق OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.execute("UPDATE users SET otp_code = ?, otp_created_at = NOW() WHERE national_id = ?", [otp, national_id]);

    // إنشاء JWT
    const token = jwt.sign({ national_id }, JWT_SECRET, { expiresIn: '1h' });
    //console.log(token)

    console.log("Secret used to sign:", process.env.JWT_SECRET);

    res.json({ message: "تم تسجيل الدخول ناجح - تم إرسال رمز التحقق", token, otp, JWT_SECRET }); // otp مؤقتًا للعرض
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "خطأ في الخادم" });
  }
});

// ✅ 3. التحقق من الرمز (Verify OTP)
app.post('/auth/verify-otp', async (req, res) => {
  const { otp } = req.body;

  if (!otp) {
    return res.status(400).json({ message: "!مطلوب رمز التحقق" });
  }

  try {
    // البحث عن المستخدم الذي يملك هذا الرمز
    const [users] = await pool.execute("SELECT * FROM users WHERE otp_code = ?", [otp]);

    if (users.length === 0) {
      return res.status(400).json({ message: "!رمز التحقق غير صحيح أو منتهي الصلاحية" });
    }

    const user = users[0];

    // (اختياري) تحقق من أن الرمز لم يمر عليه أكثر من 5 دقائق مثلاً
    const otpCreatedAt = new Date(user.otp_created_at);
    const now = new Date();
    const diffMinutes = (now - otpCreatedAt) / 1000 / 60;

    if (diffMinutes > 2) {
      return res.status(400).json({ message: "انتهت صلاحية رمز التحقق، يرجى طلب رمز جديد" });
    }

    res.json({
      message: "تم التحقق بنجاح ✅",
      national_id: user.national_id
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "خطأ في الخادم" });
  }
});


// ✅ 4. إعادة إرسال رمز التحقق (Resend OTP)
app.post('/auth/resend-otp', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ message: "مطلوب رمز الجلسة" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.execute("UPDATE users SET otp_code = ?, otp_created_at = NOW() WHERE national_id = ?", [otp, decoded.national_id]);

    res.json({ message: "تم إرسال رمز جديد", otp });
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: "رمز الجلسة غير صالح" });
  }
});

// ✅ 5. جلب بيانات البطاقة الشخصية (Get Person Card Info)
app.get('/person-card', async (req, res) => {

  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(400).json({ message: "مطلوب رمز الجلسة" });
  }

  // إزالة كلمة Bearer إن وجدت
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : authHeader;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const [rows] = await pool.execute(
      "SELECT * FROM person_card WHERE national_id = ?",
      [decoded.national_id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "لم يتم العثور على بيانات البطاقة" });
    }

    res.json({ card: rows[0] });

  } catch (err) {
    console.error("JWT Error:", err.message);
    res.status(401).json({ message: "رمز الجلسة غير صالح" });
  }

});

// ✅ 6. جلب بيانات رخصة القيادة (Get Driving license Info)
app.get('/driving-license', async (req, res) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(400).json({ message: "مطلوب رمز الجلسة" });
  }

  // إزالة كلمة Bearer إن وجدت
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : authHeader;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const [rows] = await pool.execute("SELECT * FROM driving_license WHERE national_id = ?", [decoded.national_id]);

    if (rows.length === 0) {
      return res.status(404).json({ message: "لم يتم العثور على بيانات البطاقة" });
    }

    res.json({ card: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: "رمز الجلسة غير صالح" });
  }
});

// ✅ 7. جلب البطاقات (Get Cards)
/*app.get('/citizen/cards', async (req, res) => {
    const token = req.headers['authorization']?.replace("Bearer ", "");
    if (!token) return res.status(400).json({ message: "مطلوب التوكن" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        const [rows] = await pool.execute(
            "SELECT * FROM citizen_documents WHERE national_id = ? AND document_type = 'card'",
            [decoded.national_id]
        );

        res.json({ cards: rows });
    } catch (error) {
        res.status(401).json({ message: "رمز الجلسة غير صالح" });
    }
});*/
// 📌 جلب بطاقات المواطن فقط
app.get('/citizen/cards', async (req, res) => {
    const token = req.headers['authorization']?.replace("Bearer ", "");
    if (!token) {
        return res.status(400).json({ message: "مطلوب التوكن" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        // 🔍 جلب البطاقات فقط من citizen_documents
            const [rows] = await pool.execute(
            "SELECT * FROM citizen_documents WHERE national_id = ? AND document_type = 'card'",
            [decoded.national_id]
        );

        const baseUrl = `${req.protocol}://${req.get('host')}`;

        // 🔗 تحويل المسار إلى رابط URL كامل
        const cards = rows.map(card => ({
            ...card,
            document_image_url: card.document_image_path 
                ? `${baseUrl}${card.document_image_path}` 
                : null
        }));

        return res.json({ message: "تم جلب البطاقات", cards });

    } catch (error) {
        console.error(error);
        return res.status(401).json({ message: "رمز الجلسة غير صالح" });
    }
});


// ✅ 8. جلب المستندات (Get Documents)
app.get('/citizen/documents', async (req, res) => {
    const token = req.headers['authorization']?.replace("Bearer ", "");
    if (!token) return res.status(400).json({ message: "مطلوب التوكن" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        const [rows] = await pool.execute(
            "SELECT * FROM citizen_documents WHERE national_id = ? AND document_type = 'document'",
            [decoded.national_id]
        );

        res.json({ documents: rows });
    } catch (error) {
        res.status(401).json({ message: "رمز الجلسة غير صالح" });
    }
});


// تشغيل السيرفر
app.listen(5000, () => {
  console.log('Server running on http://localhost:5000/health');
});


